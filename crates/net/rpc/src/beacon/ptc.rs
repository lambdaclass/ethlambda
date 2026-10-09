//! The payload timeliness committee's validator-facing endpoints.
//!
//! - `POST /eth/v1/validator/duties/ptc/{epoch}`: which slot of an epoch each
//!   requested validator sits in the committee (`get_ptc_assignment`).
//! - `GET /eth/v1/validator/payload_attestation_data`: what a committee member
//!   signs for a slot.
//! - `POST /eth/v1/beacon/pool/payload_attestations`: a member's signed vote,
//!   validated as gossip would, pooled for block production and gossiped.
//! - `GET /eth/v1/beacon/pool/payload_attestations`: what the pool holds,
//!   aggregated per slot and data.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use axum::{
    Extension, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ethlambda_blockchain::SyncStatusController;
use ethlambda_blockchain::metrics::SyncStatus;
use ethlambda_engine::EngineClient;
use ethlambda_network_api::RpcToP2PRef;
use ethlambda_state_transition::beacon::{
    fork_choice::get_payload_due_ms,
    gloas_block_production::aggregate_payload_attestations,
    gossip::{
        Outcome,
        payload_attestation::{SeenPayloadAttestations, cheap_checks, stateful_checks},
    },
    helpers::{accessors::get_block_root_at_slot, gloas::get_ptc_assignments},
    payload_attestation_pool::SharedPayloadAttestationPool,
    preset,
    stf::process_slots,
};
use ethlambda_storage::Store;
use ethlambda_types::{
    beacon::{
        containers::{
            BeaconState, SignedBeaconBlock,
            gloas::{PayloadAttestation, PayloadAttestationData, PayloadAttestationMessage},
        },
        fork::ForkName,
        primitives::{BlsPubkey, Epoch, Slot, ValidatorIndex},
        signing::{compute_epoch_at_slot, compute_start_slot_at_epoch},
    },
    primitives::H256,
};
use libssz::SszEncode;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::{
    CustodyColumns,
    beacon::{
        ApiError, decode_list,
        validator::{head, require_execution_client, require_validated},
    },
    shared::content::{Encoding, ssz_response, with_consensus_version},
};

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route(
            "/eth/v1/validator/duties/ptc/{epoch}",
            post(post_ptc_duties),
        )
        .route(
            "/eth/v1/validator/payload_attestation_data",
            get(get_payload_attestation_data),
        )
        .route(
            "/eth/v1/beacon/pool/payload_attestations",
            get(get_pool_payload_attestations).post(post_pool_payload_attestations),
        )
}

// ---------------------------------------------------------------------------
// Duties
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct PtcDuty {
    pubkey: BlsPubkey,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    validator_index: ValidatorIndex,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    slot: Slot,
}

/// `POST /eth/v1/validator/duties/ptc/{epoch}`.
///
/// The body is a JSON array of quoted validator indices. Each answers with the
/// first slot of `epoch` whose committee holds it: a validator with several
/// seats still gets one duty per epoch, and one in no committee gets none, as
/// does an unknown index.
///
/// `epoch` may be at most one past the wall clock's epoch (or the head's, if
/// that is later). A gloas epoch is answered
/// from the head state's `ptc_window`, which `get_ptc` can read for the
/// state's epoch, the one before and the next one. Anything else (the first
/// gloas epoch while the head is still fulu, or an epoch the head has not
/// caught up to) is answered from a copy of the head state advanced to the
/// epoch's first slot, crossing the gloas upgrade where it falls. That runs on
/// a blocking thread: on a large registry the epoch transitions are seconds
/// of work, not something to hold a runtime worker for.
///
/// An epoch before gloas has no committee, so the answer is empty rather than
/// an error: a validator client asks every epoch and reads the empty list as
/// "no duty".
///
/// `dependent_root` is the block root at `compute_start_slot_at_epoch(epoch - 1) - 1`
/// (the genesis block's at the start), the same definition the attester duties
/// use: the committee window is fixed by the state at the end of the epoch
/// before the previous one.
async fn post_ptc_duties(
    Path(epoch): Path<String>,
    State(store): State<Store>,
    body: Bytes,
) -> Response {
    let Ok(epoch) = epoch.parse::<Epoch>() else {
        return ApiError::BadRequest("invalid epoch").into_response();
    };
    let wanted = match parse_validator_indices(&body) {
        Ok(wanted) => wanted,
        Err(err) => return err.into_response(),
    };
    let computed = tokio::task::spawn_blocking(move || ptc_duties(&store, epoch, &wanted)).await;
    match computed {
        Ok(Ok(body)) => crate::json_response(body),
        Ok(Err(err)) => err.into_response(),
        Err(_) => ApiError::Internal("computing the duties failed").into_response(),
    }
}

fn parse_validator_indices(body: &[u8]) -> Result<HashSet<ValidatorIndex>, ApiError> {
    let indices = serde_json::from_slice::<Vec<String>>(body)
        .map_err(|_| ApiError::BadRequest("invalid request body"))?;
    if indices.is_empty() {
        return Err(ApiError::BadRequest("no validator indices"));
    }
    indices
        .iter()
        .map(|index| index.parse::<ValidatorIndex>())
        .collect::<Result<_, _>>()
        .map_err(|_| ApiError::BadRequest("invalid validator index"))
}

fn ptc_duties(
    store: &Store,
    epoch: Epoch,
    wanted: &HashSet<ValidatorIndex>,
) -> Result<serde_json::Value, ApiError> {
    let config = store.config();
    let (head_root, head_state) = head(store)?;
    let state_epoch = compute_epoch_at_slot(head_state.slot());
    // Bounded by the wall clock, as the other duties are (see
    // `validator::epoch_upper_bound`): the store's tick-driven clock still reads
    // the previous epoch until the boundary slot's tick runs, which is when a
    // validator client asks for the next epoch.
    if epoch > crate::beacon::validator::epoch_upper_bound(store, state_epoch) {
        return Err(ApiError::BadRequest(
            "epoch is more than one past the current",
        ));
    }

    let dependent_slot = compute_start_slot_at_epoch(epoch.saturating_sub(1)).saturating_sub(1);
    let dependent_root = if dependent_slot >= head_state.slot() {
        head_root
    } else {
        get_block_root_at_slot(&head_state, dependent_slot)
            .map_err(|_| ApiError::Internal("dependent slot is outside the state's root window"))?
    };
    let respond = |duties: Vec<PtcDuty>| {
        serde_json::json!({
            "dependent_root": dependent_root,
            "execution_optimistic": store.is_beacon_optimistic(head_root),
            "data": duties,
        })
    };

    if epoch < config.gloas_fork_epoch {
        return Ok(respond(Vec::new()));
    }
    if epoch + 1 < state_epoch {
        return Err(ApiError::BadRequest(
            "epoch is more than one before the head state's",
        ));
    }

    let readable_from_head = matches!(*head_state, BeaconState::Gloas(_))
        && epoch <= state_epoch + preset::MIN_SEED_LOOKAHEAD;
    let state: Arc<BeaconState> = if readable_from_head {
        head_state
    } else {
        let start_slot = compute_start_slot_at_epoch(epoch);
        let mut advanced = (*head_state).clone();
        process_slots(&mut advanced, start_slot, &config)
            .map_err(|_| ApiError::Internal("advancing the head state failed"))?;
        Arc::new(advanced)
    };

    let assignments = get_ptc_assignments(&state, epoch, wanted, &config)
        .map_err(|_| ApiError::Internal("the payload timeliness committee is unavailable"))?;
    let mut duties: Vec<PtcDuty> = assignments
        .into_iter()
        .filter_map(|(validator_index, slot)| {
            let pubkey = state.validator(validator_index).ok()?.pubkey;
            Some(PtcDuty {
                pubkey,
                validator_index,
                slot,
            })
        })
        .collect();
    duties.sort_by_key(|duty| (duty.slot, duty.validator_index));
    Ok(respond(duties))
}

// ---------------------------------------------------------------------------
// Payload attestation data
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct PayloadAttestationDataQuery {
    slot: Slot,
}

/// `GET /eth/v1/validator/payload_attestation_data?slot`.
///
/// For the canonical block of `slot`, meaning the block of that very slot on
/// the head's chain (the head itself when it is one). A slot with no such block
/// answers 204, which tells the validator client to cast no vote: a member
/// votes on the block of its slot, and a slot that went empty has none.
///
/// - `payload_present`: an envelope for the block reached this node before
///   `get_payload_due_ms()` into the slot, the specification's rule. A late
///   envelope, or one this node never saw, is `false`.
/// - `blob_data_available`: the bid commits to no blobs, or the payload is
///   already verified (which required them), or every column this node
///   custodies for the block is stored. Columns are verified on arrival, so
///   holding them is the evidence `is_data_available` asks for.
///
/// Refused with a `503`, like attestation data, when the block voted on has an
/// unvalidated execution payload behind it (see [`require_validated`]) and on
/// a node run without an execution client (see [`require_execution_client`]):
/// the answer is signed over the block's root, which an optimistic validator
/// must not do.
async fn get_payload_attestation_data(
    Query(query): Query<PayloadAttestationDataQuery>,
    State(store): State<Store>,
    Extension(engine): Extension<Option<EngineClient>>,
    Extension(custody): Extension<CustodyColumns>,
    Extension(sync_status): Extension<SyncStatusController>,
    headers: HeaderMap,
) -> Response {
    if let Err(err) = require_execution_client(&engine) {
        return err.into_response();
    }
    if sync_status.get() == SyncStatus::Syncing {
        return ApiError::ServiceUnavailable("node is syncing").into_response();
    }
    let data = match payload_attestation_data(&store, &custody.0, query.slot) {
        Ok(Some(data)) => data,
        Ok(None) => return StatusCode::NO_CONTENT.into_response(),
        Err(err) => return err.into_response(),
    };
    if let Err(err) = require_validated(&store, data.beacon_block_root) {
        return err.into_response();
    }
    let accept = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok());
    let response = match Encoding::from_accept(accept) {
        Encoding::Ssz => ssz_response(data.to_ssz()),
        Encoding::Json => crate::json_response(serde_json::json!({
            "version": ForkName::Gloas.as_str(),
            "data": data,
        })),
    };
    with_consensus_version(response, ForkName::Gloas)
}

/// The number of blob commitments in a gloas block's bid.
fn bid_commitment_count(block: &SignedBeaconBlock) -> Option<usize> {
    match block {
        SignedBeaconBlock::Gloas(inner) => Some(
            inner
                .message
                .body
                .signed_execution_payload_bid
                .message
                .blob_kzg_commitments
                .len(),
        ),
        _ => None,
    }
}

/// The block of `slot` on the head's chain, if there is one.
fn canonical_block_at(store: &Store, slot: Slot) -> Result<Option<H256>, ApiError> {
    let (head_slot, head_root) = store
        .beacon_head()
        .ok_or(ApiError::Internal("no head block"))?;
    if slot > head_slot {
        return Ok(None);
    }
    if slot == head_slot {
        return Ok(Some(head_root));
    }
    let (_, state) = head(store)?;
    // The state records the latest block at or before the slot, which is the
    // block of a slot only when that slot was not skipped.
    let Ok(root) = get_block_root_at_slot(&state, slot) else {
        return Ok(None);
    };
    Ok(store
        .block_slot_and_state_root(&root)
        .filter(|(block_slot, _)| *block_slot == slot)
        .map(|_| root))
}

fn payload_attestation_data(
    store: &Store,
    custody_columns: &[u64],
    slot: Slot,
) -> Result<Option<PayloadAttestationData>, ApiError> {
    let config = store.config();
    if compute_epoch_at_slot(slot) < config.gloas_fork_epoch {
        return Err(ApiError::BadRequest("slot is before the gloas fork"));
    }
    let Some(root) = canonical_block_at(store, slot)? else {
        return Ok(None);
    };
    let block = store
        .get_signed_block(&root)
        .map_err(|_| ApiError::Internal("store read failed"))?;
    let Some(commitment_count) = block.as_ref().and_then(bid_commitment_count) else {
        return Ok(None);
    };

    let due_ms = slot
        .saturating_mul(config.slot_duration_ms)
        .saturating_add(get_payload_due_ms(&config));
    let payload_present = store
        .beacon_envelope_seen_ms(&root)
        .is_some_and(|seen_ms| seen_ms < due_ms);

    let blob_data_available = commitment_count == 0 || store.has_verified_payload(&root) || {
        let present = store
            .data_column_indices_for(slot, &root)
            .map_err(|_| ApiError::Internal("store read failed"))?;
        custody_columns
            .iter()
            .all(|column| present.contains(column))
    };

    Ok(Some(PayloadAttestationData {
        beacon_block_root: root,
        slot,
        payload_present,
        blob_data_available,
    }))
}

// ---------------------------------------------------------------------------
// Pool
// ---------------------------------------------------------------------------

/// One rejected message, in the Beacon API's `IndexedErrorMessage` shape: its
/// position in the submitted array, and why.
#[derive(Debug, Serialize)]
struct Failure {
    index: usize,
    message: String,
}

/// `POST /eth/v1/beacon/pool/payload_attestations`.
///
/// Each message goes through the checks gossip applies to a peer's
/// (`validate_payload_attestation_message_gossip`: the current slot, a known
/// block at the slot, committee membership, the signature), since a vote that
/// fails them is one every peer would score this node down for relaying.
/// A valid one is pooled for block production, gossiped, and handed to the
/// chain actor by the publish path (gossip never delivers a node its own
/// messages), the others are reported by position and the rest still go out.
async fn post_pool_payload_attestations(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    Extension(pool): Extension<SharedPayloadAttestationPool>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(err) = require_gloas_or_absent(&headers) {
        return err.into_response();
    }
    let messages = match decode_list::<PayloadAttestationMessage>(&headers, &body) {
        Ok(messages) => messages,
        Err(err) => return err.into_response(),
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0);
    // Not P2P's seen cache: that holds what peers sent, and says nothing about
    // what this node's own validators submit. The pool's own dedup covers a
    // repeat.
    let seen = SeenPayloadAttestations::new(std::num::NonZeroUsize::MIN);
    let mut failures = Vec::new();
    for (index, message) in messages.into_iter().enumerate() {
        let slot = message.data.slot;
        let validator = message.validator_index;
        let verdict = match cheap_checks(&seen, &store, &message, now_ms) {
            Ok(()) => stateful_checks(&store, &message),
            Err(outcome) => outcome,
        };
        if verdict != Outcome::Accept {
            let (outcome, reason) = verdict.labels();
            warn!(%slot, validator, outcome, reason, "Refused a submitted payload attestation");
            failures.push(Failure {
                index,
                message: format!("{outcome}: {reason}"),
            });
            continue;
        }
        let first = pool
            .lock()
            .expect("payload attestation pool lock poisoned")
            .insert(message.clone());
        if !first {
            debug!(%slot, validator, "Payload attestation already pooled; not republishing");
            continue;
        }
        match p2p.publish_payload_attestation_message(message) {
            Ok(()) => debug!(%slot, validator, "Accepted payload attestation for gossip"),
            Err(_) => failures.push(Failure {
                index,
                message: "the network actor is not running".to_string(),
            }),
        }
    }

    if failures.is_empty() {
        return StatusCode::OK.into_response();
    }
    let body = serde_json::json!({
        "code": 400,
        "message": "some payload attestations failed validation and were not published",
        "failures": failures,
    });
    let mut response = crate::json_response(body);
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
}

/// `Eth-Consensus-Version` is optional here, and must name gloas when given:
/// the container exists from that fork alone.
fn require_gloas_or_absent(headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(value) = headers.get("eth-consensus-version") else {
        return Ok(());
    };
    match value.to_str().ok().and_then(ForkName::parse) {
        Some(ForkName::Gloas | ForkName::Heze) => Ok(()),
        _ => Err(ApiError::BadRequest(
            "Eth-Consensus-Version must name gloas or heze",
        )),
    }
}

#[derive(Debug, Deserialize)]
struct PoolQuery {
    slot: Option<Slot>,
}

/// `GET /eth/v1/beacon/pool/payload_attestations?slot=`: the votes this node
/// holds as `PayloadAttestation`s, those of `slot` only when given.
///
/// The pool keeps the unaggregated messages (block production combines the
/// ones it needs), but the specification's response is the aggregate: one per
/// distinct `PayloadAttestationData`, its bitvector over the slot's committee
/// and one aggregated signature. Aggregated here with the logic block
/// production uses, against the head state, which can read the committee of
/// the slot it is in, the one before and the next one. A slot outside that
/// window has no readable committee, so its votes are left out rather than
/// listed unaggregated; the pool only ever accepts the current slot's votes,
/// so in practice that is a vote the head has since left far behind.
async fn get_pool_payload_attestations(
    Query(query): Query<PoolQuery>,
    State(store): State<Store>,
    Extension(pool): Extension<SharedPayloadAttestationPool>,
) -> Response {
    let held = pool
        .lock()
        .expect("payload attestation pool lock poisoned")
        .all(query.slot);
    let aggregated = tokio::task::spawn_blocking(move || aggregate_pool(&store, held)).await;
    let data = match aggregated {
        Ok(Ok(data)) => data,
        Ok(Err(err)) => return err.into_response(),
        Err(_) => return ApiError::Internal("aggregating the pool failed").into_response(),
    };
    with_consensus_version(
        crate::json_response(serde_json::json!({
            "version": ForkName::Gloas.as_str(),
            "data": data,
        })),
        ForkName::Gloas,
    )
}

/// Group `held` by slot and aggregate each slot's votes against the head state.
fn aggregate_pool(
    store: &Store,
    held: Vec<PayloadAttestationMessage>,
) -> Result<Vec<PayloadAttestation>, ApiError> {
    let config = store.config();
    let (_, state) = head(store)?;
    let mut by_slot: BTreeMap<Slot, Vec<PayloadAttestationMessage>> = BTreeMap::new();
    for message in held {
        by_slot.entry(message.data.slot).or_default().push(message);
    }
    Ok(by_slot
        .into_iter()
        .flat_map(|(slot, messages)| {
            aggregate_payload_attestations(&state, slot, messages, &config)
        })
        .map(|(_, attestation)| attestation)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{RecordingNetwork, gloas_beacon_block};
    use axum::{body::Body, http::Request};
    use ethlambda_state_transition::beacon::{
        constants::DOMAIN_PTC_ATTESTER,
        helpers::{
            accessors::get_domain,
            misc::compute_signing_root,
            test_state::{sign_for, with_signing_validators_at},
        },
    };
    use ethlambda_storage::{ForkCheckpoints, backend::InMemoryBackend};
    use ethlambda_types::beacon::{config::Config, primitives::KzgCommitment};
    use ethlambda_types::checkpoint::Checkpoint;
    use ethlambda_types::primitives::HashTreeRoot as _;
    use http_body_util::BodyExt as _;
    use libssz::SszDecode;
    use tower::ServiceExt as _;

    const COUNT: usize = preset::PTC_WINDOW_LENGTH;

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// A gloas state with every `ptc_window` entry naming its own window index
    /// as the whole committee, so the validator a slot's committee holds is
    /// readable straight off the window layout.
    fn gloas_state() -> BeaconState {
        let mut state = with_signing_validators_at(ForkName::Gloas, COUNT);
        let BeaconState::Gloas(inner) = &mut state else {
            unreachable!("built as gloas")
        };
        // Distinct roots per slot, so a `dependent_root` read from the wrong
        // slot shows up.
        for slot in 0..inner.block_roots.len() {
            inner.block_roots[slot] = H256::repeat_byte(slot as u8 + 1);
        }
        for index in 0..preset::PTC_WINDOW_LENGTH {
            inner.ptc_window[index] = vec![index as u64; preset::PTC_SIZE]
                .try_into()
                .expect("built at exactly PTC_SIZE");
        }
        state
    }

    /// The window index (and so the validator, see [`gloas_state`]) of the
    /// `offset`th slot of `epoch`, for a state in `state_epoch`.
    fn window_index(state_epoch: Epoch, epoch: Epoch, offset: u64) -> u64 {
        (epoch + 1 - state_epoch) * preset::SLOTS_PER_EPOCH + offset
    }

    /// A store whose head is a gloas block at `state`'s slot with
    /// `commitments` blob commitments in its bid, on a clock that has that
    /// slot running now (the gossip checks only take the current slot).
    fn store_with_head(state: BeaconState, config: Config, commitments: usize) -> (Store, H256) {
        let slot = state.slot();
        store_with_head_at_clock(state, config, commitments, slot)
    }

    /// [`store_with_head`] whose wall clock is at `clock_slot` while the store's
    /// own tick-driven time stays at the head's slot, as it does until the
    /// boundary slot's tick runs.
    fn store_with_head_at_clock(
        state: BeaconState,
        config: Config,
        commitments: usize,
        clock_slot: u64,
    ) -> (Store, H256) {
        let slot = state.slot();
        let mut block = gloas_beacon_block(slot, H256::ZERO, H256::ZERO, H256::repeat_byte(1));
        let SignedBeaconBlock::Gloas(inner) = &mut block else {
            unreachable!("built as gloas")
        };
        inner
            .message
            .body
            .signed_execution_payload_bid
            .message
            .blob_kzg_commitments = vec![KzgCommitment::default(); commitments]
            .try_into()
            .expect("a few commitments fit");
        let root = block.message_hash_tree_root();
        let slot_secs = config.slot_duration_ms / 1000;
        let genesis = now_secs() - clock_slot * slot_secs - 1;
        let mut store = Store::init_beacon(
            Arc::new(InMemoryBackend::default()),
            genesis,
            config,
            root,
            Checkpoint { root, slot },
            slot,
        );
        let tick_ms = store.config().genesis_time_ms() + slot * store.config().slot_duration_ms;
        store.set_time_ms(tick_ms).unwrap();
        store.insert_signed_block(root, block).unwrap();
        store.insert_state(root, state).unwrap();
        store
            .update_checkpoints(ForkCheckpoints::head_only(root))
            .unwrap();
        (store, root)
    }

    fn gloas_config() -> Config {
        Config::mainnet().with_fork_epoch(ForkName::Gloas, 0)
    }

    struct Reply {
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
    }

    impl Reply {
        fn json(&self) -> serde_json::Value {
            serde_json::from_slice(&self.body).unwrap()
        }
    }

    async fn send(
        store: Store,
        pool: SharedPayloadAttestationPool,
        network: Arc<RecordingNetwork>,
        custody: Vec<u64>,
        sync: SyncStatusController,
        request: Request<Body>,
    ) -> Reply {
        let p2p: RpcToP2PRef = network;
        let response = routes()
            .with_state(store)
            .layer(Extension(p2p))
            .layer(Extension(pool))
            .layer(Extension(CustodyColumns(custody)))
            .layer(Extension(crate::test_utils::idle_engine()))
            .layer(Extension(sync))
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        Reply {
            status,
            headers,
            body,
        }
    }

    async fn request(store: Store, request: Request<Body>) -> Reply {
        send(
            store,
            Default::default(),
            Default::default(),
            Vec::new(),
            Default::default(),
            request,
        )
        .await
    }

    fn duties_request(epoch: u64, body: &str) -> Request<Body> {
        Request::post(format!("/eth/v1/validator/duties/ptc/{epoch}"))
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    // ----- duties ----------------------------------------------------------

    #[tokio::test]
    async fn duties_are_read_from_the_window_for_the_previous_current_and_next_epoch() {
        let state = gloas_state();
        let state_epoch = compute_epoch_at_slot(state.slot());
        let head_slot = state.slot();
        let (store, head_root) = store_with_head(state, gloas_config(), 0);
        for epoch in [state_epoch - 1, state_epoch, state_epoch + 1] {
            let validator = window_index(state_epoch, epoch, 3);
            let reply = request(
                store.clone(),
                duties_request(epoch, &format!(r#"["{validator}","9999"]"#)),
            )
            .await;
            assert_eq!(reply.status, StatusCode::OK);
            let json = reply.json();
            // The unknown validator has no duty; the other sits in its slot.
            assert_eq!(json["data"].as_array().unwrap().len(), 1);
            assert_eq!(json["data"][0]["validator_index"], validator.to_string());
            assert_eq!(
                json["data"][0]["slot"],
                (compute_start_slot_at_epoch(epoch) + 3).to_string()
            );
            assert!(
                json["data"][0]["pubkey"]
                    .as_str()
                    .unwrap()
                    .starts_with("0x")
            );
            assert_eq!(json["execution_optimistic"], false);
            // The block before the previous epoch's start; the head itself
            // when that slot is not before the head's.
            let dependent_slot =
                compute_start_slot_at_epoch(epoch.saturating_sub(1)).saturating_sub(1);
            let expected = if dependent_slot >= head_slot {
                head_root
            } else {
                H256::repeat_byte(dependent_slot as u8 + 1)
            };
            assert_eq!(json["dependent_root"], format!("{expected:?}"));
        }
    }

    #[tokio::test]
    async fn a_validator_with_several_seats_gets_its_first_slot_once() {
        let mut state = gloas_state();
        let state_epoch = compute_epoch_at_slot(state.slot());
        let BeaconState::Gloas(inner) = &mut state else {
            unreachable!("built as gloas")
        };
        let early = window_index(state_epoch, state_epoch, 5) as usize;
        let late = window_index(state_epoch, state_epoch, 9) as usize;
        inner.ptc_window[early][1] = 77;
        inner.ptc_window[late][0] = 77;
        inner.ptc_window[late][1] = 77;
        let (store, _) = store_with_head(state, gloas_config(), 0);

        let reply = request(store, duties_request(state_epoch, r#"["77"]"#)).await;

        let json = reply.json();
        assert_eq!(json["data"].as_array().unwrap().len(), 1);
        assert_eq!(
            json["data"][0]["slot"],
            (compute_start_slot_at_epoch(state_epoch) + 5).to_string()
        );
    }

    #[tokio::test]
    async fn malformed_bodies_and_far_epochs_are_a_400() {
        let state = gloas_state();
        let state_epoch = compute_epoch_at_slot(state.slot());
        let (store, _) = store_with_head(state, gloas_config(), 0);
        for body in ["[]", "not json", r#"["x"]"#, r#"[1]"#, r#"{"a":1}"#] {
            let reply = request(store.clone(), duties_request(state_epoch, body)).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
        }
        let reply = request(store.clone(), duties_request(state_epoch + 2, r#"["1"]"#)).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        let reply = request(store, duties_request(u64::MAX, r#"["1"]"#)).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    }

    /// The devnet case: the wall clock is in the epoch after the head's while
    /// the store's own clock has not ticked past the head's, and the validator
    /// client asks for the epoch after that.
    #[tokio::test]
    async fn the_bound_is_the_wall_clock_not_the_stores_tick() {
        use ethlambda_state_transition::beacon::fork_choice::get_current_slot;

        let state = gloas_state();
        let head_epoch = compute_epoch_at_slot(state.slot());
        let clock_slot = compute_start_slot_at_epoch(head_epoch + 1);
        let (store, _) = store_with_head_at_clock(state, gloas_config(), 0, clock_slot);
        let tick_epoch = compute_epoch_at_slot(get_current_slot(&store, &store.config()));
        assert_eq!(
            tick_epoch, head_epoch,
            "the store's tick is behind the clock"
        );

        let reply = request(store.clone(), duties_request(head_epoch + 2, r#"["1"]"#)).await;
        assert_eq!(reply.status, StatusCode::OK);

        let reply = request(store, duties_request(head_epoch + 3, r#"["1"]"#)).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_pre_gloas_epoch_is_answered_with_no_duties() {
        let state = gloas_state();
        let state_epoch = compute_epoch_at_slot(state.slot());
        // Gloas starts after the head's epoch, so the head's own epoch has no
        // committee even though the state happens to be gloas-shaped.
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, state_epoch + 1);
        let (store, _) = store_with_head(state, config, 0);

        let reply = request(store, duties_request(state_epoch, r#"["1","2"]"#)).await;

        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.json()["data"], serde_json::json!([]));
        assert!(reply.json()["dependent_root"].is_string());
    }

    /// While the head is still fulu, the first gloas epoch is answered from a
    /// copy of the head state advanced across the upgrade.
    #[tokio::test]
    async fn the_first_gloas_epoch_is_computed_from_a_fulu_head() {
        use ethlambda_state_transition::beacon::helpers::fulu::initialize_proposer_lookahead;
        let mut state = with_signing_validators_at(ForkName::Fulu, COUNT);
        let lookahead = initialize_proposer_lookahead(&state).unwrap();
        let BeaconState::Fulu(fulu) = &mut state else {
            unreachable!("built as fulu")
        };
        fulu.proposer_lookahead = lookahead.try_into().unwrap();
        let head_epoch = compute_epoch_at_slot(state.slot());
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, head_epoch + 1);
        let (store, _root) = crate::test_utils::beacon_store_with_config(state, config);
        let everyone =
            serde_json::to_string(&(0..COUNT as u64).map(|i| i.to_string()).collect::<Vec<_>>())
                .unwrap();

        let reply = request(store.clone(), duties_request(head_epoch + 1, &everyone)).await;

        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        let duties = reply.json()["data"].as_array().unwrap().clone();
        assert!(
            !duties.is_empty(),
            "the committee seats some of the registry"
        );
        let first_slot = compute_start_slot_at_epoch(head_epoch + 1);
        for duty in &duties {
            let slot: u64 = duty["slot"].as_str().unwrap().parse().unwrap();
            assert!((first_slot..first_slot + preset::SLOTS_PER_EPOCH).contains(&slot));
        }
        // The fulu epoch itself has none.
        let reply = request(store, duties_request(head_epoch, &everyone)).await;
        assert_eq!(reply.json()["data"], serde_json::json!([]));
    }

    // ----- payload attestation data ----------------------------------------

    fn data_request(slot: u64, accept: Option<&str>) -> Request<Body> {
        let mut request = Request::get(format!(
            "/eth/v1/validator/payload_attestation_data?slot={slot}"
        ));
        if let Some(accept) = accept {
            request = request.header("accept", accept);
        }
        request.body(Body::empty()).unwrap()
    }

    fn due_ms(store: &Store, slot: u64) -> u64 {
        let config = store.config();
        slot * config.slot_duration_ms + get_payload_due_ms(&config)
    }

    #[tokio::test]
    async fn the_data_names_the_head_block_and_defaults_to_nothing_seen() {
        let state = gloas_state();
        let slot = state.slot();
        let (store, root) = store_with_head(state, gloas_config(), 0);

        let reply = request(store, data_request(slot, None)).await;

        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.headers["eth-consensus-version"], "gloas");
        let json = reply.json();
        assert_eq!(json["version"], "gloas");
        assert_eq!(json["data"]["beacon_block_root"], format!("{root:?}"));
        assert_eq!(json["data"]["slot"], slot.to_string());
        assert_eq!(json["data"]["payload_present"], false);
        // No commitments, so there is no blob data to wait for.
        assert_eq!(json["data"]["blob_data_available"], true);
    }

    #[tokio::test]
    async fn payload_present_needs_an_envelope_seen_before_the_payload_deadline() {
        let slot = gloas_state().slot();
        let present_when_seen_at = |offset: i64| async move {
            let (mut store, root) = store_with_head(gloas_state(), gloas_config(), 0);
            let seen = (due_ms(&store, slot) as i64 + offset) as u64;
            store.insert_beacon_envelope_seen(root, slot, seen);
            request(store, data_request(slot, None)).await.json()["data"]["payload_present"].clone()
        };

        assert_eq!(present_when_seen_at(-1).await, true);
        // The deadline itself is already late.
        assert_eq!(present_when_seen_at(0).await, false);
        assert_eq!(present_when_seen_at(1_000).await, false);
    }

    #[tokio::test]
    async fn blob_availability_follows_the_custody_columns_unless_the_payload_is_verified() {
        let slot = gloas_state().slot();
        let ask = |store: Store| async move {
            send(
                store,
                Default::default(),
                Default::default(),
                vec![0, 1],
                Default::default(),
                data_request(slot, None),
            )
            .await
            .json()["data"]["blob_data_available"]
                .clone()
        };
        let (store, root) = store_with_head(gloas_state(), gloas_config(), 1);

        assert_eq!(ask(store.clone()).await, false);
        store
            .put_data_column_sidecar(slot, &root, 0, vec![1])
            .unwrap();
        assert_eq!(ask(store.clone()).await, false);
        store
            .put_data_column_sidecar(slot, &root, 1, vec![1])
            .unwrap();
        assert_eq!(ask(store.clone()).await, true);

        // A verified payload had its data, whatever columns are stored.
        let (mut store, root) = store_with_head(gloas_state(), gloas_config(), 1);
        let envelope = crate::test_utils::gloas_envelope(root, slot);
        store.insert_verified_payload(slot, &envelope);
        assert_eq!(ask(store).await, true);
    }

    #[tokio::test]
    async fn a_slot_without_a_block_is_a_204_and_a_pre_gloas_slot_a_400() {
        let state = gloas_state();
        let slot = state.slot();
        let (store, _) = store_with_head(state, gloas_config(), 0);
        for missing in [slot + 1, slot - 1] {
            let reply = request(store.clone(), data_request(missing, None)).await;
            assert_eq!(reply.status, StatusCode::NO_CONTENT, "slot {missing}");
            assert!(reply.body.is_empty());
        }

        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 5);
        let (store, _) = store_with_head(gloas_state(), config, 0);
        let reply = request(store, data_request(slot, None)).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn the_data_is_served_as_ssz_on_request_and_refused_while_syncing() {
        let state = gloas_state();
        let slot = state.slot();
        let (store, root) = store_with_head(state, gloas_config(), 0);

        let reply = request(
            store.clone(),
            data_request(slot, Some("application/octet-stream")),
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.headers["eth-consensus-version"], "gloas");
        assert_eq!(reply.headers["content-type"], "application/octet-stream");
        let data = PayloadAttestationData::from_ssz_bytes(&reply.body).unwrap();
        assert_eq!(data.beacon_block_root, root);
        assert_eq!(data.slot, slot);

        let reply = send(
            store,
            Default::default(),
            Default::default(),
            Vec::new(),
            SyncStatusController::new(SyncStatus::Syncing),
            data_request(slot, None),
        )
        .await;
        assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// The answer is signed over the block's root, so it follows attestation
    /// data's rule: no execution client is a `503`.
    #[tokio::test]
    async fn the_data_is_refused_without_an_execution_client() {
        let state = gloas_state();
        let slot = state.slot();
        let (store, _) = store_with_head(state, gloas_config(), 0);

        let p2p: RpcToP2PRef = Arc::new(RecordingNetwork::default());
        let response = routes()
            .with_state(store)
            .layer(Extension(p2p))
            .layer(Extension(CustodyColumns(Vec::new())))
            .layer(Extension(None::<EngineClient>))
            .layer(Extension(SyncStatusController::default()))
            .oneshot(data_request(slot, None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // ----- pool ------------------------------------------------------------

    /// A vote by `validator` on the head block at the head's slot, signed under
    /// the state's PTC domain unless `sign` is false.
    fn vote(
        state: &BeaconState,
        root: H256,
        validator: u64,
        sign: bool,
    ) -> PayloadAttestationMessage {
        let data = PayloadAttestationData {
            beacon_block_root: root,
            slot: state.slot(),
            payload_present: true,
            blob_data_available: true,
        };
        let domain = get_domain(
            state,
            DOMAIN_PTC_ATTESTER,
            Some(compute_epoch_at_slot(data.slot)),
        );
        let signing_root = compute_signing_root(data.hash_tree_root(), domain);
        PayloadAttestationMessage {
            validator_index: validator,
            data,
            signature: if sign {
                sign_for(validator as usize, signing_root)
            } else {
                Default::default()
            },
        }
    }

    fn submit(messages: &[PayloadAttestationMessage], version: Option<&str>) -> Request<Body> {
        let mut request = Request::post("/eth/v1/beacon/pool/payload_attestations");
        if let Some(version) = version {
            request = request.header("eth-consensus-version", version);
        }
        request
            .body(Body::from(serde_json::to_vec(messages).unwrap()))
            .unwrap()
    }

    async fn submit_to(
        store: Store,
        messages: &[PayloadAttestationMessage],
        version: Option<&str>,
    ) -> (Reply, SharedPayloadAttestationPool, Arc<RecordingNetwork>) {
        let pool = SharedPayloadAttestationPool::default();
        let network = Arc::new(RecordingNetwork::default());
        let reply = send(
            store,
            pool.clone(),
            network.clone(),
            Vec::new(),
            Default::default(),
            submit(messages, version),
        )
        .await;
        (reply, pool, network)
    }

    #[tokio::test]
    async fn a_valid_vote_is_pooled_and_published_once() {
        let state = gloas_state();
        let state_epoch = compute_epoch_at_slot(state.slot());
        let member = window_index(state_epoch, state_epoch, 0);
        let (store, root) = store_with_head(state.clone(), gloas_config(), 0);
        let message = vote(&state, root, member, true);

        let (reply, pool, network) =
            submit_to(store, &[message.clone(), message.clone()], Some("gloas")).await;

        assert_eq!(reply.status, StatusCode::OK, "{:?}", reply.body);
        assert_eq!(pool.lock().unwrap().all(None), vec![message.clone()]);
        // The repeat is neither re-pooled nor re-gossiped.
        assert_eq!(*network.payload_attestations.lock().unwrap(), vec![message]);
    }

    #[tokio::test]
    async fn a_bad_vote_is_reported_by_position_and_the_rest_still_go_out() {
        let state = gloas_state();
        let state_epoch = compute_epoch_at_slot(state.slot());
        let member = window_index(state_epoch, state_epoch, 0);
        let (store, root) = store_with_head(state.clone(), gloas_config(), 0);
        let good = vote(&state, root, member, true);
        let unsigned = vote(&state, root, member, false);
        // Signed, but its sender sits in no committee of the slot.
        let outsider = vote(&state, root, 5, true);
        let mut unknown_block = vote(&state, root, member, true);
        unknown_block.data.beacon_block_root = H256::repeat_byte(0xee);

        let (reply, pool, network) = submit_to(
            store,
            &[unsigned, good.clone(), outsider, unknown_block],
            Some("gloas"),
        )
        .await;

        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        let json = reply.json();
        assert_eq!(json["code"], 400);
        let positions: Vec<u64> = json["failures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|failure| failure["index"].as_u64().unwrap())
            .collect();
        assert_eq!(positions, vec![0, 2, 3]);
        assert_eq!(pool.lock().unwrap().all(None), vec![good.clone()]);
        assert_eq!(*network.payload_attestations.lock().unwrap(), vec![good]);
    }

    #[tokio::test]
    async fn a_vote_for_another_slot_is_refused() {
        let state = gloas_state();
        let state_epoch = compute_epoch_at_slot(state.slot());
        let member = window_index(state_epoch, state_epoch, 0);
        let (store, root) = store_with_head(state.clone(), gloas_config(), 0);
        let mut stale = vote(&state, root, member, true);
        stale.data.slot -= 1;

        let (reply, pool, _) = submit_to(store, &[stale], None).await;

        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert!(pool.lock().unwrap().all(None).is_empty());
    }

    #[tokio::test]
    async fn the_consensus_version_must_be_gloas_when_given() {
        let state = gloas_state();
        let (store, root) = store_with_head(state.clone(), gloas_config(), 0);
        let message = vote(&state, root, 0, false);
        for version in ["electra", "fulu", "nonsense"] {
            let (reply, pool, _) =
                submit_to(store.clone(), std::slice::from_ref(&message), Some(version)).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{version}");
            assert!(pool.lock().unwrap().all(None).is_empty());
        }
        let reply = request(
            store,
            Request::post("/eth/v1/beacon/pool/payload_attestations")
                .body(Body::from("not json"))
                .unwrap(),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    }

    /// Lighthouse and prysm submit their payload votes as SSZ.
    #[tokio::test]
    async fn votes_are_accepted_as_ssz_and_other_content_types_are_a_415() {
        use libssz::SszEncode as _;
        let state = gloas_state();
        let state_epoch = compute_epoch_at_slot(state.slot());
        let member = window_index(state_epoch, state_epoch, 0);
        let (store, root) = store_with_head(state.clone(), gloas_config(), 0);
        let message = vote(&state, root, member, true);

        let pool = SharedPayloadAttestationPool::default();
        let network = Arc::new(RecordingNetwork::default());
        let ssz_request = Request::post("/eth/v1/beacon/pool/payload_attestations")
            .header("content-type", "application/octet-stream")
            .header("eth-consensus-version", "gloas")
            .body(Body::from(vec![message.clone()].to_ssz()))
            .unwrap();
        let reply = send(
            store.clone(),
            pool.clone(),
            network.clone(),
            Vec::new(),
            Default::default(),
            ssz_request,
        )
        .await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(*network.payload_attestations.lock().unwrap(), vec![message]);

        let reply = request(
            store,
            Request::post("/eth/v1/beacon/pool/payload_attestations")
                .header("content-type", "text/plain")
                .body(Body::from("[]"))
                .unwrap(),
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn the_pool_is_listed_as_aggregates_by_slot() {
        let state = gloas_state();
        let state_epoch = compute_epoch_at_slot(state.slot());
        let member = window_index(state_epoch, state_epoch, 0);
        let (store, root) = store_with_head(state.clone(), gloas_config(), 0);
        let pool = SharedPayloadAttestationPool::default();
        let message = vote(&state, root, member, true);

        // The previous slot's committee is its own window entry, which names
        // the validator `slot % SLOTS_PER_EPOCH` here.
        let mut earlier_state = state.clone();
        let BeaconState::Gloas(inner) = &mut earlier_state else {
            unreachable!("built as gloas")
        };
        inner.slot -= 1;
        let earlier_member = earlier_state.slot() % preset::SLOTS_PER_EPOCH;
        let older = vote(&earlier_state, root, earlier_member, true);

        // Not in the head slot's committee: nothing to aggregate it into.
        let outsider = vote(&state, root, member + 1, true);
        for held in [&older, &message, &outsider] {
            pool.lock().unwrap().insert(held.clone());
        }
        let list = |uri: String| {
            let store = store.clone();
            let pool = pool.clone();
            async move {
                send(
                    store,
                    pool,
                    Default::default(),
                    Vec::new(),
                    Default::default(),
                    Request::get(uri).body(Body::empty()).unwrap(),
                )
                .await
            }
        };

        let all = list("/eth/v1/beacon/pool/payload_attestations".to_string()).await;
        assert_eq!(all.status, StatusCode::OK);
        assert_eq!(all.headers["eth-consensus-version"], "gloas");
        assert_eq!(all.json()["version"], "gloas");
        let data = all.json()["data"].as_array().unwrap().clone();
        assert_eq!(
            data.len(),
            2,
            "one aggregate per slot, the outsider's dropped"
        );
        // Oldest slot first, each an aggregate and not a message.
        assert_eq!(data[0]["data"]["slot"], older.data.slot.to_string());
        assert_eq!(data[1]["data"]["slot"], message.data.slot.to_string());
        for aggregate in &data {
            assert!(aggregate.get("validator_index").is_none());
            // The single seat-holder fills every position of the committee.
            let bits = aggregate["aggregation_bits"].as_str().unwrap();
            assert_eq!(bits, format!("0x{}", "ff".repeat(preset::PTC_SIZE / 8)));
        }

        // It is the aggregate block production would pack, which only keeps
        // one that verifies against the state.
        let expected = ethlambda_state_transition::beacon::gloas_block_production::aggregate_payload_attestations(
            &state,
            message.data.slot,
            [message.clone()],
            &gloas_config(),
        );
        assert_eq!(expected.len(), 1);
        assert_eq!(data[1], serde_json::to_value(&expected[0].1).unwrap());

        let slot = message.data.slot;
        let one = list(format!(
            "/eth/v1/beacon/pool/payload_attestations?slot={slot}"
        ))
        .await;
        assert_eq!(one.json()["data"].as_array().unwrap().len(), 1);
        assert_eq!(one.json()["data"][0]["data"]["slot"], slot.to_string());
    }
}
