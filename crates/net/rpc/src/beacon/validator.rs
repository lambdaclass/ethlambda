//! The validator-facing endpoints under `/eth/v{1,2}/validator/`: what a
//! validator client asks a beacon node for in order to do its duties.
//!
//! Every answer is computed from the fork-choice head's post-state, read off
//! the shared `Store` the chain actor writes: the head row is refreshed on each
//! import and tick, so no message to the actor is needed.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ethlambda_blockchain::{SyncStatusController, metrics::SyncStatus};
use ethlambda_engine::EngineClient;
use ethlambda_storage::Store;
use ethlambda_types::{
    beacon::{
        containers::{
            BeaconState,
            shared::{AttestationData, Checkpoint},
        },
        fork::ForkName,
        fork_choice::PayloadStatus,
        preset,
        primitives::{BlsPubkey, CommitteeIndex, Epoch, ExecutionAddress, Slot, ValidatorIndex},
        signing::{compute_epoch_at_slot, compute_start_slot_at_epoch},
    },
    primitives::H256,
};
use serde::{Deserialize, Serialize};

use ethlambda_network_api::RpcToP2PRef;
use ethlambda_state_transition::beacon::{
    fork_choice::{checkpoint_state, get_current_store_epoch, get_head_node},
    gossip::attestation::compute_subnet_for_attestation,
    helpers::accessors::{CommitteeCacheExt as _, get_block_root_at_slot},
    helpers::altair::compute_sync_committee_period,
};

use crate::beacon::ApiError;

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route(
            "/eth/v1/validator/duties/proposer/{epoch}",
            get(get_proposer_duties),
        )
        .route(
            "/eth/v2/validator/duties/proposer/{epoch}",
            get(get_proposer_duties_v2),
        )
        .route(
            "/eth/v1/validator/duties/attester/{epoch}",
            post(post_attester_duties),
        )
        .route(
            "/eth/v1/validator/duties/sync/{epoch}",
            post(post_sync_duties),
        )
        .route("/eth/v1/validator/liveness/{epoch}", post(post_liveness))
        .route(
            "/eth/v1/validator/attestation_data",
            get(get_attestation_data),
        )
        .route(
            "/eth/v1/validator/beacon_committee_subscriptions",
            post(post_committee_subscriptions),
        )
        .route(
            "/eth/v1/validator/prepare_beacon_proposer",
            post(post_prepare_beacon_proposer),
        )
}

#[derive(Debug, Serialize)]
struct SyncDuty {
    pubkey: BlsPubkey,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    validator_index: ValidatorIndex,
    /// Every position the validator holds in the committee, quoted. A
    /// validator can hold more than one, since the committee is drawn with
    /// replacement.
    validator_sync_committee_indices: Vec<String>,
}

/// `POST /eth/v1/validator/duties/sync/{epoch}`.
///
/// Answered from the head state: its `current_sync_committee` for an epoch in
/// the head's own sync committee period, its `next_sync_committee` for the
/// period after, which is as far ahead as the Beacon API allows. An earlier
/// period is refused rather than answered from a historical state, since a
/// validator client only ever asks about the current and next period.
///
/// A requested validator that holds no seat is left out of `data`. The
/// answer is `503` while the node is syncing: the head state's committees are
/// not yet the chain's.
async fn post_sync_duties(
    Path(epoch): Path<String>,
    State(store): State<Store>,
    Extension(sync_status): Extension<SyncStatusController>,
    Json(indices): Json<Vec<String>>,
) -> Response {
    if sync_status.get() == SyncStatus::Syncing {
        return ApiError::ServiceUnavailable("the node is syncing").into_response();
    }
    match sync_duties(&store, &epoch, &indices) {
        Ok(body) => crate::json_response(body),
        Err(err) => err.into_response(),
    }
}

fn sync_duties(
    store: &Store,
    epoch: &str,
    indices: &[String],
) -> Result<serde_json::Value, ApiError> {
    let epoch = parse_epoch(epoch)?;
    let indices = indices
        .iter()
        .map(|index| index.parse::<ValidatorIndex>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ApiError::BadRequest("invalid validator index"))?;
    let (head_root, state) = head(store)?;

    let (current, next) = state
        .sync_committees()
        .map_err(|_| ApiError::BadRequest("sync committees start at altair"))?;
    let head_period = compute_sync_committee_period(compute_epoch_at_slot(state.slot()));
    let requested_period = compute_sync_committee_period(epoch);
    let committee = if requested_period == head_period {
        current
    } else if requested_period == head_period + 1 {
        next
    } else {
        return Err(ApiError::BadRequest(
            "epoch is not in the head state's current or next sync committee period",
        ));
    };

    // One pass over the committee rather than one per requested validator:
    // the committee stores pubkeys, so that is what a validator is matched by.
    let mut positions: HashMap<BlsPubkey, Vec<String>> = HashMap::new();
    for (position, pubkey) in committee.pubkeys.iter().enumerate() {
        positions
            .entry(*pubkey)
            .or_default()
            .push(position.to_string());
    }

    let mut duties = Vec::new();
    for validator_index in indices {
        let validator = state
            .validator(validator_index)
            .map_err(|_| ApiError::BadRequest("unknown validator index"))?;
        if let Some(held) = positions.get(&validator.pubkey) {
            duties.push(SyncDuty {
                pubkey: validator.pubkey,
                validator_index,
                validator_sync_committee_indices: held.clone(),
            });
        }
    }

    Ok(serde_json::json!({
        "execution_optimistic": crate::shared::optimistic::block_is_optimistic(store, head_root),
        "data": duties,
    }))
}

#[derive(Debug, Serialize)]
struct Liveness {
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    index: ValidatorIndex,
    is_live: bool,
}

/// `POST /eth/v1/validator/liveness/{epoch}`: whether this node saw each
/// validator act in `epoch`, which is what a validator client's doppelganger
/// protection asks before it signs anything.
///
/// The Beacon API leaves the source to the node's own view. A validator is
/// live if either:
/// - the head state credits it for `epoch` (a non-zero participation byte),
///   which covers everything already included on chain; or
/// - the node observed it act in `epoch`: an accepted gossip aggregate or
///   subnet attestation, an imported block's proposer, or a submission
///   through this API. That covers what no block has included yet, most of
///   the current epoch. See [`ethlambda_storage::ObservedLiveness`].
///
/// Answered for the store clock's previous, current and next epoch; the next
/// one is always `false`, and is accepted because a doppelganger check made
/// at an epoch boundary can land on it. Anything else, and an index outside
/// the head state's registry, is a `400`; the node syncing is a `503`.
async fn post_liveness(
    Path(epoch): Path<String>,
    State(store): State<Store>,
    Extension(sync_status): Extension<SyncStatusController>,
    Json(indices): Json<Vec<String>>,
) -> Response {
    if sync_status.get() == SyncStatus::Syncing {
        return ApiError::ServiceUnavailable("the node is syncing").into_response();
    }
    match liveness(&store, &epoch, &indices) {
        Ok(body) => crate::json_response(body),
        Err(err) => err.into_response(),
    }
}

fn liveness(store: &Store, epoch: &str, indices: &[String]) -> Result<serde_json::Value, ApiError> {
    let epoch = parse_epoch(epoch)?;
    let indices = indices
        .iter()
        .map(|index| index.parse::<ValidatorIndex>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ApiError::BadRequest("invalid validator index"))?;

    let current = get_current_store_epoch(store, &store.config());
    if epoch + 1 < current || epoch > current + 1 {
        return Err(ApiError::BadRequest(
            "epoch is not the previous, current or next epoch",
        ));
    }

    let (_head_root, state) = head(store)?;
    let state_epoch = compute_epoch_at_slot(state.slot());
    // The head state's flags for `epoch`, if it keeps them: its own epoch's
    // and the one before. `None` before altair, which keeps no flags.
    let participation = state
        .altair_validator_lists()
        .ok()
        .and_then(|(previous, current, _)| {
            if epoch == state_epoch {
                Some(current)
            } else if epoch + 1 == state_epoch {
                Some(previous)
            } else {
                None
            }
        });

    let observed = store.observed_liveness();
    let mut data = Vec::with_capacity(indices.len());
    for index in indices {
        state
            .validator(index)
            .map_err(|_| ApiError::BadRequest("unknown validator index"))?;
        let credited = participation
            .and_then(|flags| flags.get(index as usize))
            .is_some_and(|flags| *flags != 0);
        data.push(Liveness {
            index,
            is_live: credited || observed.is_live(epoch, index),
        });
    }
    Ok(serde_json::json!({ "data": data }))
}

/// One entry of `beacon_committee_subscriptions`. Parsed so a malformed body
/// is refused, though `validator_index` is never read.
#[derive(Debug, Deserialize)]
struct CommitteeSubscription {
    #[allow(dead_code)]
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    validator_index: ValidatorIndex,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    committee_index: CommitteeIndex,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    committees_at_slot: u64,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    slot: Slot,
    is_aggregator: bool,
}

/// `POST /eth/v1/validator/beacon_committee_subscriptions`.
///
/// Each aggregator's entry has the node join its committee's attestation
/// subnet until the end of that slot, so the committee's votes reach the pool
/// the aggregate endpoint answers from (phase0 `validator.md`, "Attestation
/// subnet subscription"). Non-aggregators' entries need nothing: publishing
/// reaches a subnet through gossipsub fanout without joining it.
async fn post_committee_subscriptions(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    Json(subscriptions): Json<Vec<CommitteeSubscription>>,
) -> Response {
    let config = store.config();
    let subnets: Vec<(u64, Slot)> = subscriptions
        .iter()
        .filter(|entry| entry.is_aggregator)
        .map(|entry| {
            let subnet_id = compute_subnet_for_attestation(
                entry.committees_at_slot,
                entry.slot,
                entry.committee_index,
                &config,
            );
            (subnet_id, entry.slot)
        })
        .collect();
    if !subnets.is_empty() && p2p.subscribe_attestation_subnets(subnets).is_err() {
        return ApiError::Internal("the network actor is not running").into_response();
    }
    axum::http::StatusCode::OK.into_response()
}

/// Each validator's execution-layer fee recipient, as its validator client
/// last named it. Read by block production, which puts the proposer's into
/// the payload attributes. In memory only: a validator client repeats the call
/// every epoch, so a restarted node relearns the map within one.
pub(crate) type FeeRecipients = Arc<std::sync::Mutex<HashMap<ValidatorIndex, ExecutionAddress>>>;

/// One entry of `prepare_beacon_proposer`.
#[derive(Debug, Deserialize)]
struct ProposerPreparation {
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    validator_index: ValidatorIndex,
    fee_recipient: ExecutionAddress,
}

/// `POST /eth/v1/validator/prepare_beacon_proposer`: record where each
/// validator's block rewards should be paid.
async fn post_prepare_beacon_proposer(
    Extension(fee_recipients): Extension<FeeRecipients>,
    Json(preparations): Json<Vec<ProposerPreparation>>,
) -> Response {
    let mut map = fee_recipients.lock().expect("fee recipient lock poisoned");
    for preparation in preparations {
        map.insert(preparation.validator_index, preparation.fee_recipient);
    }
    axum::http::StatusCode::OK.into_response()
}

fn parse_epoch(epoch: &str) -> Result<Epoch, ApiError> {
    epoch
        .parse()
        .map_err(|_| ApiError::BadRequest("invalid epoch"))
}

/// The fork-choice head's block root and post-state.
pub(crate) fn head(store: &Store) -> Result<(H256, Arc<BeaconState>), ApiError> {
    let (_slot, root) = store
        .beacon_head()
        .ok_or(ApiError::Internal("no head block"))?;
    let state = store
        .get_state(&root)
        .map_err(|_| ApiError::Internal("store read failed"))?
        .ok_or(ApiError::Internal("head state not found"))?;
    Ok((root, state))
}

/// Refuses with a `503` while `root`'s execution payload is still unvalidated.
///
/// For the endpoints whose answer a validator signs over a block root:
/// `optimistic-sync.md` forbids an optimistic validator to attest, and the
/// Beacon API makes it the node's job to refuse ("A 503 error must be returned
/// if the block identified by the response `beacon_block_root` is
/// optimistic"). The validator client cannot tell on its own, since execution
/// status never reaches it, and a `503` is also what sends it to its next
/// beacon node.
///
/// Not a lasting refusal: a `VALID` from the execution client clears the root,
/// and the actor asks through `forkchoiceUpdated` at least once a slot.
pub(crate) fn require_validated(store: &Store, root: H256) -> Result<(), ApiError> {
    if crate::shared::optimistic::block_is_optimistic(store, root) {
        return Err(ApiError::ServiceUnavailable(
            "the block's execution payload has not been validated yet",
        ));
    }
    Ok(())
}

/// Refuses with a `503` on a node run without an execution client.
///
/// [`require_validated`]'s companion, for the same endpoints. Nothing
/// validates a payload on such a node: blocks import as
/// `PayloadValidity::NotRequired` and never join the optimistic set, so
/// [`require_validated`] alone would pass a block that nobody checked.
pub(crate) fn require_execution_client(engine: &Option<EngineClient>) -> Result<(), ApiError> {
    if engine.is_none() {
        return Err(ApiError::ServiceUnavailable(
            "no execution client configured to validate payloads with",
        ));
    }
    Ok(())
}

/// The root of the latest block at or before `slot`, on the chain ending in
/// `head_root`, whose post-state is `head_state`.
///
/// The Beacon API defines each duty's `dependent_root` as
/// `get_block_root_at_slot(state, slot)`, which only answers for a slot before
/// the state's own. A slot at or past the head's is one no block has filled
/// since the head, so the head itself is the latest block at or before it.
///
/// A slot older than the state's retained root window is an error rather than
/// a guess: a wrong `dependent_root` would let a validator client keep duties
/// a reorg has invalidated. A duty's dependent slot is at most two epochs back,
/// far inside the window, so this should never fire.
fn block_root_at_or_before(
    head_state: &BeaconState,
    head_root: H256,
    slot: Slot,
) -> Result<H256, ApiError> {
    if slot >= head_state.slot() {
        return Ok(head_root);
    }
    get_block_root_at_slot(head_state, slot)
        .map_err(|_| ApiError::Internal("dependent slot is outside the state's root window"))
}

#[derive(Debug, Serialize)]
struct ProposerDuty {
    pubkey: BlsPubkey,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    validator_index: ValidatorIndex,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    slot: Slot,
}

/// The last slot before `epoch`: v1 proposer duties' dependent slot.
fn last_slot_before(epoch: Epoch) -> Slot {
    compute_start_slot_at_epoch(epoch).saturating_sub(1)
}

/// The last slot before the epoch preceding `epoch`: the dependent slot of
/// attester duties and of v2 proposer duties. Saturates to genesis, so epochs
/// 0 and 1 both depend on the genesis block.
fn last_slot_before_previous(epoch: Epoch) -> Slot {
    last_slot_before(epoch.saturating_sub(1))
}

/// `GET /eth/v1/validator/duties/proposer/{epoch}`, deprecated by the Beacon
/// API in favour of v2.
///
/// `dependent_root` is v1's definition, the block root at
/// `compute_start_slot_at_epoch(epoch) - 1` (the genesis block's at epoch 0).
/// It is what `ethlambda validator` compares across fetches to notice a reorg.
async fn get_proposer_duties(Path(epoch): Path<String>, State(store): State<Store>) -> Response {
    match proposer_duties(&store, &epoch, last_slot_before) {
        Ok(body) => crate::json_response(body),
        Err(err) => err.into_response(),
    }
}

/// `GET /eth/v2/validator/duties/proposer/{epoch}`: v1's duties, with
/// `dependent_root` at `compute_start_slot_at_epoch(epoch - 1) - 1` (the
/// genesis block's on underflow).
///
/// That is the block fulu's lookahead depends on: an epoch's proposers are
/// written into `proposer_lookahead` by the epoch transition into the epoch
/// before it, from the state the blocks before that transition left. v1's
/// later root also changes on reorgs that leave the duties as they were.
async fn get_proposer_duties_v2(Path(epoch): Path<String>, State(store): State<Store>) -> Response {
    match proposer_duties(&store, &epoch, last_slot_before_previous) {
        Ok(body) => crate::json_response(body),
        Err(err) => err.into_response(),
    }
}

/// Proposer duties for `epoch`, with `dependent_root` the block at the slot
/// `dependent_slot` names for it, which is all that differs between versions.
///
/// Read from the `proposer_lookahead` fulu introduced and gloas keeps, which
/// the state keeps for its own epoch and the next `MIN_SEED_LOOKAHEAD` epochs, so any epoch in that window
/// is answered without advancing a state. Any other epoch is refused.
fn proposer_duties(
    store: &Store,
    epoch: &str,
    dependent_slot: fn(Epoch) -> Slot,
) -> Result<serde_json::Value, ApiError> {
    let epoch = parse_epoch(epoch)?;
    let (head_root, state) = head(store)?;

    // Gloas keeps fulu's lookahead as it is, and `upgrade_to_gloas` carries it
    // over, so a fulu head already holds the first gloas epoch's proposers.
    let proposer_lookahead = match state.as_ref() {
        BeaconState::Fulu(fulu) => &fulu.proposer_lookahead,
        BeaconState::Gloas(gloas) => &gloas.proposer_lookahead,
        _ => {
            return Err(ApiError::BadRequest(
                "proposer duties are served from the proposer lookahead of fulu and gloas only",
            ));
        }
    };
    let state_epoch = compute_epoch_at_slot(state.slot());
    let offset = epoch
        .checked_sub(state_epoch)
        .filter(|offset| *offset <= preset::MIN_SEED_LOOKAHEAD)
        .ok_or(ApiError::BadRequest(
            "epoch is outside the head state's proposer lookahead",
        ))?;

    let first_slot = compute_start_slot_at_epoch(epoch);
    let window_start = (offset * preset::SLOTS_PER_EPOCH) as usize;
    let proposers = &proposer_lookahead[window_start..][..preset::SLOTS_PER_EPOCH as usize];
    let duties = proposers
        .iter()
        .zip(first_slot..)
        .map(|(&validator_index, slot)| {
            let validator = state
                .validator(validator_index)
                .map_err(|_| ApiError::Internal("lookahead names an unknown validator"))?;
            Ok(ProposerDuty {
                pubkey: validator.pubkey,
                validator_index,
                slot,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;

    let dependent_root = block_root_at_or_before(&state, head_root, dependent_slot(epoch))?;
    Ok(serde_json::json!({
        "dependent_root": dependent_root,
        "execution_optimistic": store.is_beacon_optimistic(head_root),
        "data": duties,
    }))
}

#[derive(Debug, Serialize)]
struct AttesterDuty {
    pubkey: BlsPubkey,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    validator_index: ValidatorIndex,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    committee_index: CommitteeIndex,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    committee_length: u64,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    committees_at_slot: u64,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    validator_committee_index: u64,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    slot: Slot,
}

/// `POST /eth/v1/validator/duties/attester/{epoch}`, with the validator
/// indices to report on as a JSON array of decimal strings.
///
/// The head state answers for its previous, current and next epoch as it is:
/// an epoch's committees depend only on its seed, whose RANDAO mix is fixed a
/// full epoch earlier, and on which validators are active in it, which the
/// registry records `MAX_SEED_LOOKAHEAD` epochs ahead. Any other epoch is
/// refused rather than computed from an advanced state.
///
/// `dependent_root` is the block root at
/// `compute_start_slot_at_epoch(epoch - 1) - 1` (the genesis block's on
/// underflow), per the endpoint's definition: the last block that could still
/// change this epoch's shuffling.
///
/// Every committee of the epoch is derived to find the requested validators,
/// which on a small registry is nothing but on mainnet is a full shuffle per
/// request. Caching the epoch's shuffle is a later optimization.
async fn post_attester_duties(
    Path(epoch): Path<String>,
    State(store): State<Store>,
    Json(indices): Json<Vec<String>>,
) -> Response {
    match attester_duties(&store, &epoch, &indices) {
        Ok(body) => crate::json_response(body),
        Err(err) => err.into_response(),
    }
}

fn attester_duties(
    store: &Store,
    epoch: &str,
    indices: &[String],
) -> Result<serde_json::Value, ApiError> {
    let epoch = parse_epoch(epoch)?;
    let wanted = indices
        .iter()
        .map(|index| index.parse::<ValidatorIndex>())
        .collect::<Result<std::collections::HashSet<_>, _>>()
        .map_err(|_| ApiError::BadRequest("invalid validator index"))?;
    let (head_root, state) = head(store)?;

    let state_epoch = compute_epoch_at_slot(state.slot());
    if epoch + 1 < state_epoch || epoch > state_epoch + 1 {
        return Err(ApiError::BadRequest(
            "epoch is not within one epoch of the head state's",
        ));
    }

    let committees = store.committee_cache().committees(&state, epoch);
    let committees_at_slot = committees.committees_per_slot();
    let first_slot = compute_start_slot_at_epoch(epoch);
    let mut duties = Vec::new();
    for slot in first_slot..first_slot + preset::SLOTS_PER_EPOCH {
        for committee_index in 0..committees_at_slot {
            let committee = committees
                .committee(slot, committee_index)
                .map_err(|_| ApiError::Internal("committee computation failed"))?;
            for (position, &validator_index) in committee.iter().enumerate() {
                if !wanted.contains(&validator_index) {
                    continue;
                }
                let validator = state
                    .validator(validator_index)
                    .map_err(|_| ApiError::Internal("committee names an unknown validator"))?;
                duties.push(AttesterDuty {
                    pubkey: validator.pubkey,
                    validator_index,
                    committee_index,
                    committee_length: committee.len() as u64,
                    committees_at_slot,
                    validator_committee_index: position as u64,
                    slot,
                });
            }
        }
    }

    let dependent_slot = last_slot_before_previous(epoch);
    let dependent_root = block_root_at_or_before(&state, head_root, dependent_slot)?;
    Ok(serde_json::json!({
        "dependent_root": dependent_root,
        "execution_optimistic": store.is_beacon_optimistic(head_root),
        "data": duties,
    }))
}

#[derive(Debug, Deserialize)]
struct AttestationDataQuery {
    slot: Slot,
    /// Optional, ignored and deprecated in the Beacon API (gloas's dropped it):
    /// from electra on the committee travels outside `AttestationData`, whose
    /// `index` no longer names it, so every committee of a slot attests to the
    /// same data. Parsed rather than dropped so a malformed value is still a
    /// `400`.
    #[allow(dead_code)]
    committee_index: Option<CommitteeIndex>,
}

/// `GET /eth/v1/validator/attestation_data?slot&committee_index`.
///
/// Built as phase0's `validator.md` ("Attestation data") describes, with the
/// fork-choice head as `head_block` and `head_state` its post-state advanced
/// through empty slots to `slot`:
///
/// - `beacon_block_root` is the head block's root.
/// - `source` is that advanced state's `current_justified_checkpoint`. It can
///   only change at an epoch boundary, so the state is advanced no further
///   than the start of `slot`'s epoch, through fork choice's cached
///   `checkpoint_state`, and only when the head sits in an earlier epoch.
/// - `target` is `slot`'s epoch and its boundary block: the head itself when
///   no block has filled the boundary slot since, else the root the state
///   recorded there.
/// - `index` is zero, as electra requires. At a gloas slot it is the
///   payload-present flag instead; see [`payload_present_index`].
///
/// A slot before the head's, or more than one slot past the wall clock, is
/// refused: neither is a slot a validator is asked to attest to. So is an
/// optimistic head, with a `503` (see [`require_validated`]); because of the
/// first refusal, the head is always the `beacon_block_root` answered.
///
/// So is every request, with a `503`, on a node run without an execution
/// client (see [`require_execution_client`]). Block production refuses the
/// same way, for its own reason.
async fn get_attestation_data(
    Query(query): Query<AttestationDataQuery>,
    State(store): State<Store>,
    Extension(engine): Extension<Option<EngineClient>>,
) -> Response {
    if let Err(err) = require_execution_client(&engine) {
        return err.into_response();
    }
    match attestation_data(&store, query.slot) {
        Ok(data) => crate::json_response(serde_json::json!({ "data": data })),
        Err(err) => err.into_response(),
    }
}

fn attestation_data(store: &Store, slot: Slot) -> Result<AttestationData, ApiError> {
    let (head_root, state) = head(store)?;
    if slot < state.slot() {
        return Err(ApiError::BadRequest("slot is before the head block"));
    }
    if slot > crate::beacon::node::wall_slot(store) + 1 {
        return Err(ApiError::BadRequest("slot is in the future"));
    }
    require_validated(store, head_root)?;

    let epoch = compute_epoch_at_slot(slot);
    let epoch_start = compute_start_slot_at_epoch(epoch);
    let source = if compute_epoch_at_slot(state.slot()) == epoch {
        state.current_justified_checkpoint()
    } else {
        let boundary = Checkpoint {
            epoch,
            root: head_root,
        };
        checkpoint_state(store, &boundary, &store.config())
            .map_err(|_| ApiError::Internal("advancing the head state failed"))?
            .current_justified_checkpoint()
    };
    let target = Checkpoint {
        epoch,
        root: block_root_at_or_before(&state, head_root, epoch_start)?,
    };

    let index = if store.config().fork_at_epoch(epoch) == ForkName::Gloas {
        payload_present_index(store, &state, slot)?
    } else {
        0
    };

    Ok(AttestationData {
        slot,
        index,
        beacon_block_root: head_root,
        source,
        target,
    })
}

/// `data.index` of a gloas attestation for `slot` voting for the head block
/// whose post-state is `head_state` (`specs/gloas/validator.md`, "Attestation
/// data"): `0` when the head block is from `slot` itself, since its payload
/// cannot have been revealed yet, else `1` iff this node's fork choice holds
/// the head block's payload as FULL.
///
/// The head's payload status is the one fork choice recorded with its head
/// ([`Store::head_payload_status`]); it is `None` until this process has
/// computed a head, or while the recorded node is not the current head, and
/// then the walk is run once to find out. A pre-gloas head counts as FULL, the
/// boundary rule this node's fork choice applies too
/// (`docs/spec_deviations.md`), so the first gloas slots vote for the last
/// fulu block's payload.
fn payload_present_index(
    store: &Store,
    head_state: &BeaconState,
    slot: Slot,
) -> Result<u64, ApiError> {
    if head_state.slot() == slot {
        return Ok(0);
    }
    if !matches!(head_state, BeaconState::Gloas(_)) {
        return Ok(1);
    }
    let status = match store.head_payload_status() {
        Some(status) => status,
        None => {
            get_head_node(store, &store.config())
                .map_err(|_| ApiError::Internal("fork choice head lookup failed"))?
                .payload_status
        }
    };
    Ok(u64::from(status == PayloadStatus::Full))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{beacon_store_at, idle_engine};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use ethlambda_state_transition::beacon::helpers::{
        fulu::{get_beacon_proposer_indices, initialize_proposer_lookahead},
        test_state::with_signing_validators_at,
    };
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::fork::ForkName;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    const COUNT: usize = 64;

    /// A fulu state one epoch past genesis with its lookahead filled in, as
    /// every real fulu state has it, and distinct block roots per slot so a
    /// `dependent_root` taken from the wrong slot shows up.
    fn fulu_state() -> BeaconState {
        let mut state = with_signing_validators_at(ForkName::Fulu, COUNT);
        let lookahead = initialize_proposer_lookahead(&state).unwrap();
        let BeaconState::Fulu(fulu) = &mut state else {
            unreachable!("built as fulu")
        };
        fulu.proposer_lookahead = lookahead.try_into().unwrap();
        for slot in 0..fulu.block_roots.len() {
            fulu.block_roots[slot] = H256::repeat_byte(slot as u8 + 1);
        }
        state
    }

    async fn get(state: BeaconState, uri: &str) -> (StatusCode, serde_json::Value) {
        let (store, _root) = beacon_store_at(state);
        let request = Request::get(uri).body(Body::empty()).unwrap();
        let response = routes().with_state(store).oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn proposers_match_the_spec_computation_for_both_lookahead_epochs() {
        let state = fulu_state();
        let state_epoch = compute_epoch_at_slot(state.slot());
        for epoch in [state_epoch, state_epoch + 1] {
            let expected = get_beacon_proposer_indices(&state, epoch).unwrap();
            let (status, json) = get(
                state.clone(),
                &format!("/eth/v1/validator/duties/proposer/{epoch}"),
            )
            .await;
            assert_eq!(status, StatusCode::OK);

            let duties = json["data"].as_array().unwrap();
            assert_eq!(duties.len(), preset::SLOTS_PER_EPOCH as usize);
            for (offset, duty) in duties.iter().enumerate() {
                let index = expected[offset];
                let slot = compute_start_slot_at_epoch(epoch) + offset as u64;
                assert_eq!(duty["validator_index"], index.to_string());
                assert_eq!(duty["slot"], slot.to_string());
                let pubkey = state.validator(index).unwrap().pubkey;
                assert_eq!(duty["pubkey"], format!("0x{}", hex::encode(pubkey.0)));
            }
        }
    }

    #[tokio::test]
    async fn the_dependent_root_is_the_block_before_the_epoch() {
        let state = fulu_state();
        let state_epoch = compute_epoch_at_slot(state.slot());
        let (_, json) = get(
            state.clone(),
            &format!("/eth/v1/validator/duties/proposer/{state_epoch}"),
        )
        .await;
        // The state sits at the first slot of its epoch, so the slot before it
        // is still in its root window.
        let before = compute_start_slot_at_epoch(state_epoch) - 1;
        let expected = get_block_root_at_slot(&state, before).unwrap();
        assert_eq!(json["dependent_root"], format!("{expected}"));
    }

    #[tokio::test]
    async fn the_next_epochs_dependent_block_is_the_head_itself() {
        // The last slot of the head's epoch has not happened yet, so the latest
        // block at or before it is the head.
        let state = fulu_state();
        let next = compute_epoch_at_slot(state.slot()) + 1;
        let (store, head_root) = beacon_store_at(state);
        let request = Request::get(format!("/eth/v1/validator/duties/proposer/{next}"))
            .body(Body::empty())
            .unwrap();
        let response = routes().with_state(store).oneshot(request).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["dependent_root"], format!("{head_root}"));
    }

    /// v2 serves v1's duties with each epoch's dependent block an epoch
    /// earlier. The head's epoch is 1, so its dependent slot underflows to
    /// genesis; the next epoch's is the last slot of epoch 0, where v1 names
    /// the head.
    #[tokio::test]
    async fn v2_dependent_root_is_the_block_before_the_previous_epoch() {
        let state = fulu_state();
        let state_epoch = compute_epoch_at_slot(state.slot());
        for epoch in [state_epoch, state_epoch + 1] {
            let v1_uri = format!("/eth/v1/validator/duties/proposer/{epoch}");
            let (_, v1) = get(state.clone(), &v1_uri).await;
            let v2_uri = format!("/eth/v2/validator/duties/proposer/{epoch}");
            let (status, v2) = get(state.clone(), &v2_uri).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(v2["data"], v1["data"]);

            let dependent = compute_start_slot_at_epoch(epoch - 1).saturating_sub(1);
            let expected = get_block_root_at_slot(&state, dependent).unwrap();
            assert_eq!(v2["dependent_root"], format!("{expected}"));
            assert_ne!(v2["dependent_root"], v1["dependent_root"]);
        }
    }

    async fn post(
        state: BeaconState,
        uri: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let (store, _root) = beacon_store_at(state);
        let request = Request::post(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = routes().with_state(store).oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn attester_duties_match_get_beacon_committee() {
        use ethlambda_state_transition::beacon::helpers::accessors::get_beacon_committee;

        let state = fulu_state();
        let epoch = compute_epoch_at_slot(state.slot());
        let (status, json) = post(
            state.clone(),
            &format!("/eth/v1/validator/duties/attester/{epoch}"),
            serde_json::json!(["3", "17"]),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let duties = json["data"].as_array().unwrap();
        // Every active validator attests exactly once per epoch.
        assert_eq!(duties.len(), 2);
        for duty in duties {
            let slot: u64 = duty["slot"].as_str().unwrap().parse().unwrap();
            let index: u64 = duty["committee_index"].as_str().unwrap().parse().unwrap();
            let position: usize = duty["validator_committee_index"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            let committee = get_beacon_committee(&state, slot, index).unwrap();
            assert_eq!(
                committee[position].to_string(),
                duty["validator_index"].as_str().unwrap()
            );
            assert_eq!(duty["committee_length"], committee.len().to_string());
            assert_eq!(compute_epoch_at_slot(slot), epoch);
        }
    }

    #[tokio::test]
    async fn an_unknown_validator_has_no_duty() {
        let state = fulu_state();
        let epoch = compute_epoch_at_slot(state.slot());
        let (status, json) = post(
            state,
            &format!("/eth/v1/validator/duties/attester/{epoch}"),
            serde_json::json!(["100000"]),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["data"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_attester_dependent_root_is_the_block_before_the_previous_epoch() {
        // For the next epoch, the dependent slot is the one before the head's
        // own epoch, which is inside the state's root window.
        let state = fulu_state();
        let next = compute_epoch_at_slot(state.slot()) + 1;
        let (_, json) = post(
            state.clone(),
            &format!("/eth/v1/validator/duties/attester/{next}"),
            serde_json::json!(["0"]),
        )
        .await;
        let before = compute_start_slot_at_epoch(next - 1) - 1;
        let expected = get_block_root_at_slot(&state, before).unwrap();
        assert_eq!(json["dependent_root"], format!("{expected}"));
    }

    #[tokio::test]
    async fn attester_duties_two_epochs_ahead_are_a_400() {
        let state = fulu_state();
        let too_far = compute_epoch_at_slot(state.slot()) + 2;
        let (status, _) = post(
            state,
            &format!("/eth/v1/validator/duties/attester/{too_far}"),
            serde_json::json!(["0"]),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// `fulu_state` moved `slots_past_boundary` slots into its epoch, with a
    /// current justified checkpoint distinct from the default so a source read
    /// from anywhere else shows up.
    fn fulu_state_at(slots_past_boundary: u64) -> BeaconState {
        let mut state = fulu_state();
        let BeaconState::Fulu(fulu) = &mut state else {
            unreachable!("built as fulu")
        };
        fulu.slot += slots_past_boundary;
        fulu.current_justified_checkpoint = Checkpoint {
            epoch: 1,
            root: H256::repeat_byte(0xaa),
        };
        state
    }

    /// `attestation_data` for `slot`, from a node whose execution client is
    /// `engine`.
    async fn fetch_attestation_data(
        store: Store,
        slot: Slot,
        engine: Option<EngineClient>,
    ) -> (StatusCode, serde_json::Value) {
        let uri = format!("/eth/v1/validator/attestation_data?slot={slot}&committee_index=0");
        let request = Request::get(uri).body(Body::empty()).unwrap();
        let app = routes().with_state(store).layer(Extension(engine));
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    async fn attestation_data_for(
        state: BeaconState,
        slot: Slot,
    ) -> (StatusCode, serde_json::Value, H256) {
        let (store, head_root) = beacon_store_at(state);
        let (status, json) = fetch_attestation_data(store, slot, idle_engine()).await;
        (status, json, head_root)
    }

    #[tokio::test]
    async fn at_the_boundary_the_head_is_the_target() {
        let state = fulu_state_at(0);
        let slot = state.slot();
        let (status, json, head_root) = attestation_data_for(state, slot).await;
        assert_eq!(status, StatusCode::OK);
        let data = &json["data"];
        assert_eq!(data["slot"], slot.to_string());
        assert_eq!(data["index"], "0");
        assert_eq!(data["beacon_block_root"], format!("{head_root}"));
        assert_eq!(
            data["target"]["epoch"],
            compute_epoch_at_slot(slot).to_string()
        );
        assert_eq!(data["target"]["root"], format!("{head_root}"));
        assert_eq!(data["source"]["epoch"], "1");
        assert_eq!(
            data["source"]["root"],
            format!("{}", H256::repeat_byte(0xaa))
        );
    }

    #[tokio::test]
    async fn past_the_boundary_the_target_is_the_recorded_boundary_block() {
        let state = fulu_state_at(3);
        let slot = state.slot() + 1;
        let boundary = compute_start_slot_at_epoch(compute_epoch_at_slot(slot));
        let expected = get_block_root_at_slot(&state, boundary).unwrap();
        let (status, json, head_root) = attestation_data_for(state, slot).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["data"]["target"]["root"], format!("{expected}"));
        assert_eq!(json["data"]["beacon_block_root"], format!("{head_root}"));
    }

    #[tokio::test]
    async fn a_head_in_the_previous_epoch_is_advanced_for_the_source() {
        // The head sits late in its epoch and the attestation is for the next
        // epoch's first slot, whose boundary no block has filled: the target is
        // the head, and the source comes from the head state advanced across
        // the boundary (unchanged here, since epoch processing leaves the
        // current justified checkpoint alone without votes).
        let state = fulu_state_at(preset::SLOTS_PER_EPOCH - 1);
        let slot = state.slot() + 1;
        let (status, json, head_root) = attestation_data_for(state, slot).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(
            json["data"]["target"]["epoch"],
            compute_epoch_at_slot(slot).to_string()
        );
        assert_eq!(json["data"]["target"]["root"], format!("{head_root}"));
        assert_eq!(
            json["data"]["source"]["root"],
            format!("{}", H256::repeat_byte(0xaa))
        );
    }

    /// No vote for a head the execution client has not validated, and an
    /// answer again once it has. The refusal is a 503, the status the Beacon
    /// API names and the one a validator client fails over on.
    #[tokio::test]
    async fn an_optimistic_head_is_a_503_until_it_is_validated() {
        let state = fulu_state_at(0);
        let slot = state.slot();
        let (mut store, head_root) = beacon_store_at(state);

        store.insert_beacon_optimistic_root(head_root, slot);
        let (status, json) = fetch_attestation_data(store.clone(), slot, idle_engine()).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(json["code"], 503);

        store.remove_beacon_optimistic_root(head_root);
        let (status, _) = fetch_attestation_data(store, slot, idle_engine()).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// Without an execution client no head is ever optimistic, since nothing
    /// was asked, so the optimistic check alone would answer. The node refuses
    /// outright instead.
    #[tokio::test]
    async fn a_node_without_an_execution_client_is_a_503() {
        let state = fulu_state_at(0);
        let slot = state.slot();
        let (store, head_root) = beacon_store_at(state);
        assert!(!store.is_beacon_optimistic(head_root));

        let (status, json) = fetch_attestation_data(store, slot, None).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(json["code"], 503);
    }

    /// `committee_index` is deprecated and optional, and gloas clients are
    /// told to omit it, so a request without one is answered. A malformed one
    /// is still refused.
    #[tokio::test]
    async fn committee_index_may_be_omitted() {
        let state = fulu_state_at(0);
        let slot = state.slot();
        let (store, _root) = beacon_store_at(state);
        let fetch = |uri: String| {
            let app = routes()
                .with_state(store.clone())
                .layer(Extension(idle_engine()));
            app.oneshot(Request::get(uri).body(Body::empty()).unwrap())
        };

        let response = fetch(format!("/eth/v1/validator/attestation_data?slot={slot}"));
        assert_eq!(response.await.unwrap().status(), StatusCode::OK);
        let malformed = format!("/eth/v1/validator/attestation_data?slot={slot}&committee_index=x");
        let response = fetch(malformed);
        assert_eq!(response.await.unwrap().status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_slot_before_the_head_is_a_400() {
        let state = fulu_state_at(3);
        let slot = state.slot() - 1;
        let (status, _, _) = attestation_data_for(state, slot).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn subscriptions_and_preparations_are_acknowledged() {
        let subscription = serde_json::json!([{
            "validator_index": "1", "committee_index": "0", "committees_at_slot": "1",
            "slot": "33", "is_aggregator": false
        }]);
        let (status, _) = post_raw(
            "/eth/v1/validator/beacon_committee_subscriptions",
            subscription,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let preparation = serde_json::json!([{
            "validator_index": "1",
            "fee_recipient": "0x000000000000000000000000000000000000dead"
        }]);
        let (status, _) = post_raw("/eth/v1/validator/prepare_beacon_proposer", preparation).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_preparation_records_the_validators_fee_recipient() {
        let (store, _) = beacon_store_at(fulu_state());
        let fee_recipients = FeeRecipients::default();
        let app = routes()
            .with_state(store)
            .layer(Extension(fee_recipients.clone()));
        let body = serde_json::json!([
            { "validator_index": "7", "fee_recipient": format!("0x{}", "ab".repeat(20)) }
        ]);
        let request = Request::post("/eth/v1/validator/prepare_beacon_proposer")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::OK);
        assert_eq!(
            fee_recipients.lock().unwrap().get(&7),
            Some(&ExecutionAddress::from_slice(&[0xab; 20]))
        );
    }

    async fn post_raw(uri: &str, body: serde_json::Value) -> (StatusCode, axum::body::Bytes) {
        let (store, _) = beacon_store_at(fulu_state());
        let request = Request::post(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let network: RpcToP2PRef = Arc::new(crate::test_utils::RecordingNetwork::default());
        let app = routes()
            .with_state(store)
            .layer(Extension(network))
            .layer(Extension(FeeRecipients::default()));
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        (
            status,
            response.into_body().collect().await.unwrap().to_bytes(),
        )
    }

    /// An aggregator's entry joins its committee's subnet until its slot; a
    /// plain attester's joins nothing.
    #[tokio::test]
    async fn only_aggregators_join_their_committee_subnet() {
        let (store, _) = beacon_store_at(fulu_state());
        let network = Arc::new(crate::test_utils::RecordingNetwork::default());
        let p2p: RpcToP2PRef = network.clone();
        let app = routes().with_state(store).layer(Extension(p2p));
        let body = serde_json::json!([
            { "validator_index": "1", "committee_index": "3", "committees_at_slot": "4",
              "slot": "34", "is_aggregator": true },
            { "validator_index": "2", "committee_index": "0", "committees_at_slot": "4",
              "slot": "34", "is_aggregator": false },
        ]);
        let request = Request::post("/eth/v1/validator/beacon_committee_subscriptions")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // Slot 34 is offset 2 in its epoch: committee 3 of 4 per slot is the
        // epoch's committee 11.
        assert_eq!(*network.subscriptions.lock().unwrap(), vec![(11, 34)]);
    }

    /// Sends the request `request` builds to a store holding a fulu head under
    /// a schedule that puts gloas one epoch past the head's: the head's epoch
    /// is the last fulu one, and the next is the first gloas one. `request`
    /// gets the head's epoch and slot.
    async fn with_gloas_next_epoch(
        request: impl Fn(Epoch, Slot) -> Request<Body>,
    ) -> (StatusCode, serde_json::Value) {
        let state = fulu_state();
        let head_slot = state.slot();
        let head_epoch = compute_epoch_at_slot(head_slot);
        let config = ethlambda_types::beacon::config::Config::mainnet()
            .with_fork_epoch(ForkName::Gloas, head_epoch + 1);
        let (store, _root) = crate::test_utils::beacon_store_with_config(state, config);
        let response = routes()
            .with_state(store)
            .layer(Extension(crate::test_utils::idle_engine()))
            .oneshot(request(head_epoch, head_slot))
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    fn get_request(uri: String) -> Request<Body> {
        Request::get(uri).body(Body::empty()).unwrap()
    }

    fn attestation_data_request(slot: Slot) -> Request<Body> {
        get_request(format!(
            "/eth/v1/validator/attestation_data?slot={slot}&committee_index=0"
        ))
    }

    #[tokio::test]
    async fn a_fulu_head_answers_the_first_gloas_epoch_for_every_duty() {
        let (status, _) = with_gloas_next_epoch(|head_epoch, _| {
            get_request(format!(
                "/eth/v1/validator/duties/proposer/{}",
                head_epoch + 1
            ))
        })
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = with_gloas_next_epoch(|head_epoch, _| {
            Request::post(format!(
                "/eth/v1/validator/duties/attester/{}",
                head_epoch + 1
            ))
            .header("content-type", "application/json")
            .body(Body::from("[\"0\"]"))
            .unwrap()
        })
        .await;
        assert_eq!(status, StatusCode::OK);

        // The head is a fulu block, which counts as FULL at the boundary.
        let (status, json) = with_gloas_next_epoch(|head_epoch, _| {
            attestation_data_request(compute_start_slot_at_epoch(head_epoch + 1))
        })
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["data"]["index"], "1");
    }

    #[tokio::test]
    async fn the_gloas_proposer_duties_match_the_lookahead_of_a_gloas_state() {
        let mut state = with_signing_validators_at(ForkName::Gloas, COUNT);
        let lookahead = initialize_proposer_lookahead(&state).unwrap();
        let BeaconState::Gloas(gloas) = &mut state else {
            unreachable!("built as gloas")
        };
        gloas.proposer_lookahead = lookahead.clone().try_into().unwrap();
        let epoch = compute_epoch_at_slot(state.slot());
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 0);
        let (store, _) = crate::test_utils::beacon_store_with_config(state, config);
        let request = get_request(format!("/eth/v1/validator/duties/proposer/{epoch}"));
        let response = routes().with_state(store).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let proposers: Vec<u64> = json["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|duty| duty["validator_index"].as_str().unwrap().parse().unwrap())
            .collect();
        assert_eq!(proposers, lookahead[..preset::SLOTS_PER_EPOCH as usize]);
    }

    /// A store whose head is a gloas state `slots_past_boundary` into its
    /// epoch, under a schedule with gloas from epoch 0, and the payload status
    /// fork choice recorded for that head.
    fn gloas_head(
        slots_past_boundary: u64,
        recorded: Option<PayloadStatus>,
    ) -> (Store, BeaconState) {
        let mut state = with_signing_validators_at(ForkName::Gloas, COUNT);
        let BeaconState::Gloas(gloas) = &mut state else {
            unreachable!("built as gloas")
        };
        gloas.slot += slots_past_boundary;
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 0);
        let (store, head_root) = crate::test_utils::beacon_store_with_config(state.clone(), config);
        if let Some(status) = recorded {
            store.set_head_payload_status(head_root, status);
        }
        (store, state)
    }

    async fn gloas_index(store: Store, slot: Slot) -> (StatusCode, serde_json::Value) {
        // No `committee_index`: gloas's request omits it.
        let request = get_request(format!("/eth/v1/validator/attestation_data?slot={slot}"));
        let response = routes()
            .with_state(store)
            .layer(Extension(idle_engine()))
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn a_gloas_vote_in_the_head_blocks_own_slot_has_index_zero() {
        let (store, state) = gloas_head(1, Some(PayloadStatus::Full));
        let (status, json) = gloas_index(store, state.slot()).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["data"]["index"], "0");
    }

    #[tokio::test]
    async fn a_gloas_vote_for_an_earlier_full_head_has_index_one() {
        let (store, state) = gloas_head(1, Some(PayloadStatus::Full));
        let (status, json) = gloas_index(store, state.slot() + 1).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["data"]["index"], "1");
    }

    #[tokio::test]
    async fn a_gloas_vote_for_an_earlier_empty_head_has_index_zero() {
        let (store, state) = gloas_head(1, Some(PayloadStatus::Empty));
        let (status, json) = gloas_index(store, state.slot() + 1).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["data"]["index"], "0");
    }

    #[tokio::test]
    async fn an_epoch_outside_the_lookahead_is_a_400() {
        let state = fulu_state();
        let too_far = compute_epoch_at_slot(state.slot()) + 2;
        for version in ["v1", "v2"] {
            let uri = format!("/eth/{version}/validator/duties/proposer/{too_far}");
            let (status, _) = get(state.clone(), &uri).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{version}");
        }
    }

    // --- duties/sync -----------------------------------------------------

    mod sync_duties {
        use super::*;
        use ethlambda_types::beacon::containers::altair::SyncCommittee;

        /// A committee whose seat `i` belongs to validator `first + i % 8`, so
        /// each of those eight holds `SYNC_COMMITTEE_SIZE / 8` seats and every
        /// other validator holds none.
        fn committee_of(state: &BeaconState, first: u64) -> SyncCommittee {
            let pubkeys: Vec<BlsPubkey> = (0..preset::SYNC_COMMITTEE_SIZE as u64)
                .map(|seat| state.validator(first + seat % 8).unwrap().pubkey)
                .collect();
            SyncCommittee {
                aggregate_pubkey: pubkeys[0],
                pubkeys: pubkeys.try_into().unwrap(),
            }
        }

        /// A fulu state whose current committee is validators 0-7 and whose
        /// next committee is validators 8-15, so an answer drawn from the
        /// wrong one shows up.
        fn state_with_committees() -> BeaconState {
            let mut state = fulu_state();
            let current = committee_of(&state, 0);
            let next = committee_of(&state, 8);
            let BeaconState::Fulu(fulu) = &mut state else {
                unreachable!("built as fulu")
            };
            fulu.current_sync_committee = current;
            fulu.next_sync_committee = next;
            state
        }

        async fn post_sync(
            state: BeaconState,
            epoch: u64,
            indices: &[&str],
            sync_status: SyncStatusController,
        ) -> (StatusCode, serde_json::Value) {
            let (store, _root) = beacon_store_at(state);
            let request = Request::post(format!("/eth/v1/validator/duties/sync/{epoch}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!(indices).to_string()))
                .unwrap();
            let app = routes().with_state(store).layer(Extension(sync_status));
            let response = app.oneshot(request).await.unwrap();
            let status = response.status();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            (status, serde_json::from_slice(&body).unwrap_or_default())
        }

        /// The seats `validator` holds in [`committee_of`]`(_, first)`.
        fn seats(validator: u64, first: u64) -> Vec<String> {
            (0..preset::SYNC_COMMITTEE_SIZE as u64)
                .filter(|seat| first + seat % 8 == validator)
                .map(|seat| seat.to_string())
                .collect()
        }

        #[tokio::test]
        async fn the_current_period_reads_the_current_committee() {
            let state = state_with_committees();
            let epoch = compute_epoch_at_slot(state.slot());
            let (status, json) =
                post_sync(state.clone(), epoch, &["3", "9", "20"], Default::default()).await;
            assert_eq!(status, StatusCode::OK);

            // Validator 3 sits in the current committee; 9 only in the next;
            // 20 in neither, so only 3 is listed.
            let duties = json["data"].as_array().unwrap();
            assert_eq!(duties.len(), 1);
            assert_eq!(duties[0]["validator_index"], "3");
            let pubkey = state.validator(3).unwrap().pubkey;
            assert_eq!(duties[0]["pubkey"], format!("0x{}", hex::encode(pubkey.0)));
            assert_eq!(
                duties[0]["validator_sync_committee_indices"],
                serde_json::json!(seats(3, 0))
            );
            assert!(json["execution_optimistic"].is_boolean());
        }

        #[tokio::test]
        async fn the_next_period_reads_the_next_committee() {
            let state = state_with_committees();
            let next_period_epoch = preset::EPOCHS_PER_SYNC_COMMITTEE_PERIOD
                * (compute_sync_committee_period(compute_epoch_at_slot(state.slot())) + 1);
            let (status, json) =
                post_sync(state, next_period_epoch, &["3", "9"], Default::default()).await;
            assert_eq!(status, StatusCode::OK);

            let duties = json["data"].as_array().unwrap();
            assert_eq!(duties.len(), 1);
            assert_eq!(duties[0]["validator_index"], "9");
            assert_eq!(
                duties[0]["validator_sync_committee_indices"],
                serde_json::json!(seats(9, 8))
            );
        }

        #[tokio::test]
        async fn the_period_after_next_is_a_400() {
            let state = state_with_committees();
            let period = compute_sync_committee_period(compute_epoch_at_slot(state.slot()));
            let epoch = preset::EPOCHS_PER_SYNC_COMMITTEE_PERIOD * (period + 2);
            let (status, _) = post_sync(state, epoch, &["3"], Default::default()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }

        /// An earlier period would need a historical state, which a validator
        /// client never asks for; refused rather than answered wrongly.
        #[tokio::test]
        async fn an_earlier_period_is_a_400() {
            let mut state = state_with_committees();
            let BeaconState::Fulu(fulu) = &mut state else {
                unreachable!("built as fulu")
            };
            fulu.slot = preset::EPOCHS_PER_SYNC_COMMITTEE_PERIOD * preset::SLOTS_PER_EPOCH;
            let (status, _) = post_sync(state, 0, &["3"], Default::default()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn an_unknown_validator_is_a_400() {
            let state = state_with_committees();
            let epoch = compute_epoch_at_slot(state.slot());
            let unknown = (COUNT as u64).to_string();
            let (status, _) = post_sync(state, epoch, &[&unknown], Default::default()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn a_syncing_node_answers_503() {
            let state = state_with_committees();
            let epoch = compute_epoch_at_slot(state.slot());
            let syncing = SyncStatusController::new(SyncStatus::Syncing);
            let (status, _) = post_sync(state, epoch, &["3"], syncing).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    // --- liveness --------------------------------------------------------

    mod liveness {
        use super::*;

        /// The epoch every test's state and store clock sit in: far enough
        /// from genesis that the epoch two before it exists.
        const EPOCH: u64 = 5;

        /// A fulu state at [`EPOCH`]'s first slot in which validator 2 is
        /// credited for this epoch and validator 3 for the previous one.
        fn credited_state() -> BeaconState {
            let mut state = fulu_state();
            let BeaconState::Fulu(fulu) = &mut state else {
                unreachable!("built as fulu")
            };
            fulu.slot = compute_start_slot_at_epoch(EPOCH);
            fulu.current_epoch_participation[2] = 0b001;
            fulu.previous_epoch_participation[3] = 0b111;
            state
        }

        /// `state`'s store, its clock moved to `state`'s slot, as the chain
        /// actor's tick keeps it.
        fn store_for(state: BeaconState) -> Store {
            let slot = state.slot();
            let (mut store, _root) = beacon_store_at(state);
            let config = store.config();
            let now = config.genesis_time_ms() + slot * config.slot_duration_ms;
            store.set_time_ms(now).unwrap();
            store
        }

        async fn post_liveness(
            store: Store,
            epoch: u64,
            indices: &[&str],
            sync_status: SyncStatusController,
        ) -> (StatusCode, serde_json::Value) {
            let request = Request::post(format!("/eth/v1/validator/liveness/{epoch}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!(indices).to_string()))
                .unwrap();
            let app = routes().with_state(store).layer(Extension(sync_status));
            let response = app.oneshot(request).await.unwrap();
            let status = response.status();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            (status, serde_json::from_slice(&body).unwrap_or_default())
        }

        /// `(index, is_live)` pairs, in the order answered.
        fn answers(json: &serde_json::Value) -> Vec<(String, bool)> {
            json["data"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| {
                    (
                        entry["index"].as_str().unwrap().to_owned(),
                        entry["is_live"].as_bool().unwrap(),
                    )
                })
                .collect()
        }

        #[tokio::test]
        async fn a_participation_flag_makes_a_validator_live() {
            let store = store_for(credited_state());
            let (status, json) =
                post_liveness(store.clone(), EPOCH, &["2", "3"], Default::default()).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                answers(&json),
                [("2".into(), true), ("3".into(), false)],
                "2 is credited for this epoch, 3 only for the previous one"
            );

            let (_, json) = post_liveness(store, EPOCH - 1, &["2", "3"], Default::default()).await;
            assert_eq!(answers(&json), [("2".into(), false), ("3".into(), true)]);
        }

        /// What no block has included yet: a validator the node saw act is
        /// live without any flag.
        #[tokio::test]
        async fn an_observed_validator_is_live_without_a_flag() {
            let store = store_for(credited_state());
            store.observed_liveness().record(EPOCH, 9);
            let (status, json) =
                post_liveness(store, EPOCH, &["9", "10"], Default::default()).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(answers(&json), [("9".into(), true), ("10".into(), false)]);
        }

        #[tokio::test]
        async fn the_next_epoch_is_answered_and_nobody_is_live_in_it() {
            let store = store_for(credited_state());
            let (status, json) = post_liveness(store, EPOCH + 1, &["2"], Default::default()).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(answers(&json), [("2".into(), false)]);
        }

        #[tokio::test]
        async fn epochs_outside_the_window_are_a_400() {
            for epoch in [EPOCH - 2, EPOCH + 2] {
                let store = store_for(credited_state());
                let (status, _) = post_liveness(store, epoch, &["2"], Default::default()).await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "epoch {epoch}");
            }
        }

        #[tokio::test]
        async fn an_unknown_validator_is_a_400() {
            let store = store_for(credited_state());
            let unknown = (COUNT as u64).to_string();
            let (status, _) = post_liveness(store, EPOCH, &[&unknown], Default::default()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn a_syncing_node_answers_503() {
            let store = store_for(credited_state());
            let syncing = SyncStatusController::new(SyncStatus::Syncing);
            let (status, _) = post_liveness(store, EPOCH, &["2"], syncing).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        }
    }
}
