//! Heze's inclusion list endpoints for validator clients (EIP-7805, the
//! Beacon API's `focil` additions):
//!
//! - `POST /eth/v1/validator/duties/inclusion_list/{epoch}`: which slot of an
//!   epoch each requested validator sits on the inclusion list committee
//!   (`get_inclusion_list_committee_assignment`).
//! - `GET /eth/v1/validator/inclusion_list?slot`: the transactions the
//!   execution client would list now (`engine_getInclusionListV1`).
//! - `POST /eth/v1/validator/inclusion_list`: a member's signed list,
//!   validated as gossip would, stored and gossiped.

use std::collections::HashSet;
use std::sync::Arc;

use axum::{
    Extension, Router,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ethlambda_engine::EngineClient;
use ethlambda_network_api::RpcToP2PRef;
use ethlambda_state_transition::beacon::{
    gossip::{
        Outcome,
        inclusion_list::{SeenInclusionLists, cheap_checks, stateful_checks},
    },
    helpers::accessors::get_block_root_at_slot,
    inclusion_list::{get_inclusion_list_committee, is_inclusion_list_timely},
    preset,
    stf::process_slots,
};
use ethlambda_storage::Store;
use ethlambda_types::beacon::{
    containers::{BeaconState, heze::SignedInclusionList},
    fork::ForkName,
    primitives::{BlsPubkey, Epoch, Slot, ValidatorIndex},
    signing::{compute_epoch_at_slot, compute_start_slot_at_epoch},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::beacon::{
    ApiError,
    validator::{epoch_upper_bound, head, require_execution_client},
};

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route(
            "/eth/v1/validator/duties/inclusion_list/{epoch}",
            post(post_inclusion_list_duties),
        )
        .route(
            "/eth/v1/validator/inclusion_list",
            get(get_inclusion_list).post(post_inclusion_list),
        )
}

// ---------------------------------------------------------------------------
// Duties
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct InclusionListDuty {
    pubkey: BlsPubkey,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    validator_index: ValidatorIndex,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::quoted_or_bare")]
    slot: Slot,
}

/// `POST /eth/v1/validator/duties/inclusion_list/{epoch}`.
///
/// The body is a JSON array of quoted validator indices. Each answers with the
/// first slot of `epoch` whose inclusion list committee holds it, as
/// `get_inclusion_list_committee_assignment` does; one on no committee gets no
/// duty. An epoch before heze has no committee, so its answer is empty rather
/// than an error.
///
/// `dependent_root` is the block root at
/// `compute_start_slot_at_epoch(epoch - 1) - 1`, the attester shuffling's,
/// which the committees are drawn from; it is also the `dependent_root` a
/// member's list names.
async fn post_inclusion_list_duties(
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
    let computed =
        tokio::task::spawn_blocking(move || inclusion_list_duties(&store, epoch, &wanted)).await;
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

fn inclusion_list_duties(
    store: &Store,
    epoch: Epoch,
    wanted: &HashSet<ValidatorIndex>,
) -> Result<serde_json::Value, ApiError> {
    let config = store.config();
    let (head_root, head_state) = head(store)?;
    let state_epoch = compute_epoch_at_slot(head_state.slot());
    if epoch > epoch_upper_bound(store, state_epoch) {
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
    let respond = |duties: Vec<InclusionListDuty>| {
        serde_json::json!({
            "dependent_root": dependent_root,
            "execution_optimistic": store.is_beacon_optimistic(head_root),
            "data": duties,
        })
    };

    if config.fork_at_epoch(epoch) != ForkName::Heze {
        return Ok(respond(Vec::new()));
    }
    if epoch + 1 < state_epoch {
        return Err(ApiError::BadRequest(
            "epoch is more than one before the head state's",
        ));
    }

    // A state answers committees for its own epoch, the one before and the
    // next one; anything later is reached by advancing a copy of the head.
    let state: Arc<BeaconState> = if epoch <= state_epoch + preset::MIN_SEED_LOOKAHEAD {
        head_state
    } else {
        let mut advanced = (*head_state).clone();
        process_slots(&mut advanced, compute_start_slot_at_epoch(epoch), &config)
            .map_err(|_| ApiError::Internal("advancing the head state failed"))?;
        Arc::new(advanced)
    };

    let committees = store.committee_cache();
    let start_slot = compute_start_slot_at_epoch(epoch);
    let mut assigned: HashSet<ValidatorIndex> = HashSet::new();
    let mut duties = Vec::new();
    for slot in start_slot..start_slot + preset::SLOTS_PER_EPOCH {
        let committee = get_inclusion_list_committee(&state, slot, &*committees)
            .map_err(|_| ApiError::Internal("the inclusion list committee is unavailable"))?;
        for validator_index in committee {
            if !wanted.contains(&validator_index) || !assigned.insert(validator_index) {
                continue;
            }
            let Ok(validator) = state.validator(validator_index) else {
                continue;
            };
            duties.push(InclusionListDuty {
                pubkey: validator.pubkey,
                validator_index,
                slot,
            });
        }
    }
    duties.sort_by_key(|duty| (duty.slot, duty.validator_index));
    Ok(respond(duties))
}

// ---------------------------------------------------------------------------
// Producing a list
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct InclusionListQuery {
    slot: Slot,
}

/// `GET /eth/v1/validator/inclusion_list?slot`: the transactions the
/// execution client would put in an inclusion list now, from its view of the
/// mempool, as `0x`-prefixed hex. The validator client builds and signs the
/// `InclusionList` around them. Refused with a `503` on a node with no
/// execution client, and a `400` for a slot that is not heze's.
async fn get_inclusion_list(
    State(store): State<Store>,
    Extension(engine): Extension<Option<EngineClient>>,
    query: Result<Query<InclusionListQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return ApiError::BadRequest("slot is required").into_response();
    };
    if store
        .config()
        .fork_at_epoch(compute_epoch_at_slot(query.slot))
        != ForkName::Heze
    {
        return ApiError::BadRequest("the slot is not a heze slot").into_response();
    }
    if let Err(err) = require_execution_client(&engine) {
        return err.into_response();
    }
    let Some(engine) = engine else {
        unreachable!("require_execution_client refused a missing engine");
    };
    match engine.get_inclusion_list_v1().await {
        Ok(transactions) => {
            let data: Vec<String> = transactions
                .iter()
                .map(|transaction| format!("0x{}", hex::encode(transaction)))
                .collect();
            crate::json_response(serde_json::json!({ "data": data }))
        }
        Err(err) => {
            warn!(slot = query.slot, %err, "engine_getInclusionListV1 failed");
            ApiError::ServiceUnavailable("the execution client did not return an inclusion list")
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Publishing a list
// ---------------------------------------------------------------------------

/// The body `publishInclusionList` takes: the list under `data`. A bare list
/// is accepted too, the shape every other submission endpoint takes.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PublishBody {
    Wrapped { data: SignedInclusionList },
    Bare(SignedInclusionList),
}

/// `POST /eth/v1/validator/inclusion_list`.
///
/// The list goes through the checks gossip applies to a peer's
/// (`validate_inclusion_list_gossip`), since one that fails them is one every
/// peer would score this node down for relaying; a valid one is stored with
/// its timeliness, which block production and the payload checks read, and
/// gossiped on `inclusion_list`.
async fn post_inclusion_list(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(value) = headers.get("eth-consensus-version")
        && value.to_str().ok().and_then(ForkName::parse) != Some(ForkName::Heze)
    {
        return ApiError::BadRequest("Eth-Consensus-Version must name heze").into_response();
    }
    let signed = match serde_json::from_slice::<PublishBody>(&body) {
        Ok(PublishBody::Wrapped { data }) | Ok(PublishBody::Bare(data)) => data,
        Err(_) => {
            return ApiError::BadRequest("the body is not a SignedInclusionList").into_response();
        }
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0);
    // Not P2P's seen counts: those hold what peers sent, and a node never
    // receives its own messages. The store's own dedup covers a repeat.
    let seen = SeenInclusionLists::new(std::num::NonZeroUsize::MIN);
    let verdict = match cheap_checks(&seen, &store, &signed, now_ms) {
        Ok(()) => {
            let (store, signed) = (store.clone(), signed.clone());
            match tokio::task::spawn_blocking(move || stateful_checks(&store, &signed)).await {
                Ok(verdict) => verdict,
                Err(_) => {
                    return ApiError::Internal("validating the inclusion list failed")
                        .into_response();
                }
            }
        }
        Err(outcome) => outcome,
    };
    let slot = signed.message.slot;
    let validator = signed.message.validator_index;
    if verdict != Outcome::Accept {
        let (outcome, reason) = verdict.labels();
        warn!(%slot, validator, outcome, reason, "Refused a submitted inclusion list");
        let body = serde_json::json!({
            "code": 400,
            "message": format!("the inclusion list failed validation: {outcome}: {reason}"),
        });
        let mut response = crate::json_response(body);
        *response.status_mut() = StatusCode::BAD_REQUEST;
        return response;
    }

    let timely = is_inclusion_list_timely(&store.config(), slot, now_ms);
    let stored = store
        .inclusion_list_store()
        .process_inclusion_list(signed.clone(), timely);
    if !stored {
        debug!(%slot, validator, "Inclusion list already stored; not republishing");
        return StatusCode::OK.into_response();
    }
    match p2p.publish_inclusion_list(signed) {
        Ok(()) => {
            debug!(%slot, validator, timely, "Accepted inclusion list for gossip");
            StatusCode::OK.into_response()
        }
        Err(_) => ApiError::ServiceUnavailable("the network actor is not running").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{RecordingNetwork, gloas_beacon_block};
    use axum::{body::Body, http::Request};
    use ethlambda_state_transition::beacon::{
        helpers::test_state::with_signing_validators_at, upgrade::upgrade_to_heze,
    };
    use ethlambda_storage::{ForkCheckpoints, backend::InMemoryBackend};
    use ethlambda_types::beacon::{
        config::Config,
        containers::heze::{InclusionList, SignedInclusionList},
    };
    use ethlambda_types::checkpoint::Checkpoint;
    use ethlambda_types::primitives::H256;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    const COUNT: usize = 256;

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn heze_config() -> Config {
        Config::mainnet()
            .with_fork_epoch(ForkName::Gloas, 0)
            .with_fork_epoch(ForkName::Heze, 0)
    }

    /// A store whose head is a block at a heze state's slot, on a clock with
    /// that slot running now.
    fn heze_store(config: Config) -> (Store, H256) {
        let gloas = with_signing_validators_at(ForkName::Gloas, COUNT);
        let state = upgrade_to_heze(&gloas, &config).unwrap();
        let slot = state.slot();
        let block = gloas_beacon_block(slot, H256::ZERO, H256::ZERO, H256::repeat_byte(1));
        let root = block.message_hash_tree_root();
        let slot_secs = config.slot_duration_ms / 1000;
        let genesis = now_secs() - slot * slot_secs - 1;
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

    async fn send(
        store: Store,
        network: Arc<RecordingNetwork>,
        request: Request<Body>,
    ) -> (StatusCode, serde_json::Value) {
        let p2p: RpcToP2PRef = network;
        let response = routes()
            .with_state(store)
            .layer(Extension(p2p))
            .layer(Extension(None::<EngineClient>))
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    fn duties_request(epoch: u64, indices: &[u64]) -> Request<Body> {
        let body: Vec<String> = indices.iter().map(u64::to_string).collect();
        Request::post(format!("/eth/v1/validator/duties/inclusion_list/{epoch}"))
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap()
    }

    #[tokio::test]
    async fn duties_name_each_validators_first_committee_slot() {
        let (store, _) = heze_store(heze_config());
        let (_, head_state) = head(&store).unwrap();
        let epoch = compute_epoch_at_slot(head_state.slot());
        let all: Vec<u64> = (0..COUNT as u64).collect();
        let (status, body) = send(
            store.clone(),
            Default::default(),
            duties_request(epoch, &all),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Every committee member of the epoch gets exactly its first slot.
        let committees = store.committee_cache();
        let start = compute_start_slot_at_epoch(epoch);
        let mut expected = std::collections::BTreeMap::new();
        for slot in start..start + preset::SLOTS_PER_EPOCH {
            for member in get_inclusion_list_committee(&head_state, slot, &*committees).unwrap() {
                expected.entry(member).or_insert(slot);
            }
        }
        let duties = body["data"].as_array().unwrap();
        assert_eq!(duties.len(), expected.len());
        for duty in duties {
            let index: u64 = duty["validator_index"].as_str().unwrap().parse().unwrap();
            let slot: u64 = duty["slot"].as_str().unwrap().parse().unwrap();
            assert_eq!(expected.get(&index), Some(&slot), "validator {index}");
        }
        assert!(body["dependent_root"].is_string());
    }

    #[tokio::test]
    async fn a_pre_heze_epoch_has_no_duties() {
        let config = heze_config().with_fork_epoch(ForkName::Heze, 1_000);
        let (store, _) = heze_store(config);
        let (status, body) = send(store, Default::default(), duties_request(0, &[0, 1])).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"].as_array().unwrap().len(), 0);
    }

    fn publish_request(version: &str, signed: &SignedInclusionList) -> Request<Body> {
        Request::post("/eth/v1/validator/inclusion_list")
            .header("content-type", "application/json")
            .header("eth-consensus-version", version)
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({ "data": signed })).unwrap(),
            ))
            .unwrap()
    }

    #[tokio::test]
    async fn a_list_that_fails_the_gossip_rules_is_refused_and_not_published() {
        let (store, root) = heze_store(heze_config());
        let slot = store.beacon_head().unwrap().0;
        // No transactions: gossip ignores an empty list.
        let signed = SignedInclusionList {
            message: InclusionList {
                slot,
                validator_index: 0,
                dependent_root: root,
                transactions: Default::default(),
            },
            signature: Default::default(),
        };
        let network = Arc::new(RecordingNetwork::default());
        let (status, _) = send(store, network.clone(), publish_request("heze", &signed)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(network.inclusion_lists.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_list_under_another_forks_version_is_refused() {
        let (store, root) = heze_store(heze_config());
        let signed = SignedInclusionList {
            message: InclusionList {
                dependent_root: root,
                ..Default::default()
            },
            signature: Default::default(),
        };
        let (status, _) = send(store, Default::default(), publish_request("gloas", &signed)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn producing_a_list_needs_an_execution_client() {
        let (store, _) = heze_store(heze_config());
        let slot = store.beacon_head().unwrap().0;
        let request = Request::get(format!("/eth/v1/validator/inclusion_list?slot={slot}"))
            .body(Body::empty())
            .unwrap();
        let (status, _) = send(store, Default::default(), request).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }
}
