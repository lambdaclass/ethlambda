//! `GET /eth/v3/validator/blocks/{slot}` (`produceBlockV3`), a block for a
//! validator client to sign with its payload built by this node's own
//! execution client, and `POST /eth/v2/beacon/blocks` (`publishBlockV2`), the
//! signed block back to gossip and import.
//!
//! Only unblinded, locally built blocks: this node has no builder flow, so
//! `builder_boost_factor` is accepted and ignored, and every answer carries
//! `Eth-Execution-Payload-Blinded: false`.
//!
//! Payloads carrying blobs are refused for now, with a 503 the validator client
//! fails over on. Publishing such a block means computing and gossiping its
//! data column sidecars, which this node does not do yet, and a block its peers
//! cannot sample is a block they will not import.

use axum::{
    Extension, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ethlambda_engine::{
    EngineClient, ForkchoiceStateV1,
    building::{BuiltPayload, PayloadAttributesV3},
    types::uint256,
};
use ethlambda_network_api::RpcToP2PRef;
use ethlambda_state_transition::beacon::{
    attestation_pool::SharedAttestationPool,
    block_production::{
        BlockInputs, advance_to_slot, assemble_block, pack_attestations, parse_execution_requests,
        payload_inputs,
    },
    stf::verify_block_signature,
};
use ethlambda_storage::Store;
use ethlambda_types::{
    beacon::{
        config::Config,
        containers::{
            self, BeaconState,
            deneb::Blob,
            electra::{BeaconBlock, SignedBeaconBlock},
        },
        fork::ForkName,
        preset,
        primitives::{BlsSignature, Bytes32, ExecutionAddress, KzgProof, Slot},
        signing::compute_epoch_at_slot,
    },
    primitives::H256,
};
use libssz::{SszDecode as _, SszEncode as _};
use libssz_derive::{SszDecode, SszEncode};
use libssz_types::SszList;
use serde::Deserialize;
use tracing::{info, warn};

use crate::beacon::{ApiError, validator::FeeRecipients, validator::head};
use crate::shared::content::{Encoding, ssz_response, with_consensus_version};

/// One KZG proof per cell of every blob, fulu's `kzg_proofs` bound.
pub(crate) type CellKzgProofs = SszList<
    KzgProof,
    { preset::FIELD_ELEMENTS_PER_EXT_BLOB * preset::MAX_BLOB_COMMITMENTS_PER_BLOCK },
>;
pub(crate) type Blobs = SszList<Blob, { preset::MAX_BLOB_COMMITMENTS_PER_BLOCK }>;

/// Fulu's `BlockContents`, the Beacon API's envelope for an unblinded block
/// and the blobs its proposer publishes with it. A beacon-APIs container, not
/// a consensus one, so it lives with the API.
#[derive(Debug, Clone, PartialEq, SszEncode, SszDecode, serde::Serialize)]
pub(crate) struct FuluBlockContents {
    pub(crate) block: BeaconBlock,
    #[serde(serialize_with = "ethlambda_types::beacon::serde_helpers::seq::serialize")]
    pub(crate) kzg_proofs: CellKzgProofs,
    #[serde(serialize_with = "ethlambda_types::beacon::serde_helpers::ssz_hex_seq::serialize")]
    pub(crate) blobs: Blobs,
}

/// Fulu's `SignedBlockContents`, what `publishBlockV2` receives.
#[derive(Debug, Clone, PartialEq, SszEncode, SszDecode)]
pub(crate) struct FuluSignedBlockContents {
    pub(crate) signed_block: SignedBeaconBlock,
    pub(crate) kzg_proofs: CellKzgProofs,
    pub(crate) blobs: Blobs,
}

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route("/eth/v3/validator/blocks/{slot}", get(get_block))
        .route(
            "/eth/v2/beacon/blocks",
            post(post_block).layer(DefaultBodyLimit::max(super::MAX_PUBLISH_BODY_BYTES)),
        )
}

/// `POST /eth/v2/beacon/blocks`, SSZ-encoded `SignedBlockContents`.
///
/// Checked before it goes anywhere: the fork is fulu, it carries no blobs
/// (whose data columns this node cannot publish yet, see the module docs), it
/// builds on this node's head, and the proposer's signature verifies against
/// the head state advanced to its slot. Then handed to P2P, which gossips it
/// and gives it to the chain actor to import. The full import runs there, so
/// `200` here means validated and broadcast, the `gossip` level of
/// `broadcast_validation`, which is the endpoint's default.
async fn post_block(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let fork = headers
        .get("eth-consensus-version")
        .and_then(|value| value.to_str().ok())
        .and_then(ForkName::parse);
    if !matches!(fork, Some(ForkName::Fulu | ForkName::Gloas)) {
        return ApiError::BadRequest("Eth-Consensus-Version must be fulu or gloas").into_response();
    }
    let is_ssz = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with(crate::SSZ_CONTENT_TYPE));
    if !is_ssz {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "blocks are accepted as application/octet-stream only",
        )
            .into_response();
    }
    if fork == Some(ForkName::Gloas) {
        return post_gloas_block(&store, &p2p, &body).await;
    }
    let Ok(contents) = FuluSignedBlockContents::from_ssz_bytes(&body) else {
        return ApiError::BadRequest("the body is not fulu SignedBlockContents").into_response();
    };
    if !contents.blobs.is_empty()
        || !contents.kzg_proofs.is_empty()
        || !contents
            .signed_block
            .message
            .body
            .blob_kzg_commitments
            .is_empty()
    {
        return ApiError::BadRequest(
            "blocks with blobs are not accepted yet: their data columns cannot be published",
        )
        .into_response();
    }

    let block = containers::SignedBeaconBlock::Fulu(contents.signed_block);
    let (_, head_state) = match head(&store) {
        Ok(found) => found,
        Err(err) => return err.into_response(),
    };
    if block.slot() <= head_state.slot() {
        return ApiError::BadRequest("the block is not after this node's head").into_response();
    }
    if let Err(err) = require_fulu_slot(
        &store.config(),
        block.slot(),
        "blocks are accepted for fulu slots only",
    ) {
        return err.into_response();
    }
    let Ok(state) = advance_to_slot(&head_state, block.slot(), &store.config()) else {
        return ApiError::Internal("advancing the head state failed").into_response();
    };
    if !verify_block_signature(&state, &block) {
        return ApiError::BadRequest("invalid block signature").into_response();
    }
    if p2p.publish_beacon_block(block).is_err() {
        return ApiError::Internal("the network actor is not running").into_response();
    }
    StatusCode::OK.into_response()
}

/// The gloas half of `publishBlockV2`: a bare SSZ `SignedBeaconBlock`, since a
/// gloas block carries no payload and no blobs of its own (the envelope and
/// the data columns follow through `publishExecutionPayloadEnvelope`).
///
/// Checked as the fulu one is, before it goes anywhere: the parent is held,
/// the slot is after the parent's and scheduled at gloas, the proposer is the
/// slot's, and the proposer's signature verifies against the parent's state
/// advanced to the slot. The advance and the signature are CPU-bound and run
/// off the runtime.
async fn post_gloas_block(store: &Store, p2p: &RpcToP2PRef, body: &[u8]) -> Response {
    let Ok(signed) = containers::gloas::SignedBeaconBlock::from_ssz_bytes(body) else {
        return ApiError::BadRequest("the body is not a gloas SignedBeaconBlock").into_response();
    };
    let block = containers::SignedBeaconBlock::Gloas(signed);
    let config = store.config();
    if let Err(err) = require_gloas_slot(
        &config,
        block.slot(),
        "blocks are accepted for gloas slots only",
    ) {
        return err.into_response();
    }
    let parent_state = match store.get_state(&block.parent_root()) {
        Ok(Some(state)) => state,
        Ok(None) => return ApiError::BadRequest("the block's parent is not held").into_response(),
        Err(_) => return ApiError::Internal("store read failed").into_response(),
    };
    if block.slot() <= parent_state.slot() {
        return ApiError::BadRequest("the block is not after its parent").into_response();
    }
    let verdict = {
        let block = block.clone();
        tokio::task::spawn_blocking(move || {
            let state = advance_to_slot(&parent_state, block.slot(), &config)
                .map_err(|_| ApiError::Internal("advancing the parent state failed"))?;
            let expected =
                ethlambda_state_transition::beacon::helpers::accessors::get_beacon_proposer_index(
                    &state,
                )
                .map_err(|_| ApiError::Internal("no proposer for the slot"))?;
            if block.proposer_index() != expected {
                return Err(ApiError::BadRequest(
                    "the block's proposer is not the slot's",
                ));
            }
            if !verify_block_signature(&state, &block) {
                return Err(ApiError::BadRequest("invalid block signature"));
            }
            Ok(())
        })
        .await
    };
    match verdict {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return err.into_response(),
        Err(_) => return ApiError::Internal("verifying the block failed").into_response(),
    }
    if p2p.publish_beacon_block(block).is_err() {
        return ApiError::Internal("the network actor is not running").into_response();
    }
    StatusCode::OK.into_response()
}

/// Refuses a slot the schedule does not place at gloas.
pub(crate) fn require_gloas_slot(
    config: &Config,
    slot: Slot,
    message: &'static str,
) -> Result<(), ApiError> {
    match config.fork_at_epoch(compute_epoch_at_slot(slot)) {
        ForkName::Gloas => Ok(()),
        ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb
        | ForkName::Electra
        | ForkName::Fulu
        | ForkName::Lean => Err(ApiError::BadRequest(message)),
    }
}

#[derive(Debug, Deserialize)]
struct ProduceQuery {
    randao_reveal: BlsSignature,
    #[serde(default)]
    graffiti: Option<H256>,
}

/// Refuses a slot the schedule does not place at fulu, before anything
/// advances a state to it: advancing a fulu head into a gloas slot would run
/// `upgrade_to_gloas` only to refuse the result. Every other fork is refused
/// too, since the containers here are fulu's.
fn require_fulu_slot(config: &Config, slot: Slot, message: &'static str) -> Result<(), ApiError> {
    match config.fork_at_epoch(compute_epoch_at_slot(slot)) {
        ForkName::Fulu => Ok(()),
        ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb
        | ForkName::Electra
        | ForkName::Gloas
        | ForkName::Lean => Err(ApiError::BadRequest(message)),
    }
}

async fn get_block(
    Path(slot): Path<String>,
    Query(query): Query<ProduceQuery>,
    State(store): State<Store>,
    Extension(engine): Extension<Option<EngineClient>>,
    Extension(pool): Extension<SharedAttestationPool>,
    Extension(fee_recipients): Extension<FeeRecipients>,
    headers: HeaderMap,
) -> Response {
    let Ok(slot) = slot.parse::<Slot>() else {
        return ApiError::BadRequest("invalid slot").into_response();
    };
    // Ahead of the engine check: a slot this node cannot build is a 400 on
    // any node, not a 503 on one with no execution client.
    if let Err(err) = require_fulu_slot(
        &store.config(),
        slot,
        "block production is served for fulu only",
    ) {
        return err.into_response();
    }
    let Some(engine) = engine else {
        return ApiError::ServiceUnavailable(
            "no execution client configured to build a payload with",
        )
        .into_response();
    };
    let graffiti = query.graffiti.unwrap_or(Bytes32::ZERO);
    let produced = produce(
        &store,
        &engine,
        &pool,
        &fee_recipients,
        slot,
        query.randao_reveal,
        graffiti,
    )
    .await;
    let (block, payload_value, fork) = match produced {
        Ok(produced) => produced,
        Err(err) => return err.into_response(),
    };

    let contents = FuluBlockContents {
        block,
        kzg_proofs: Default::default(),
        blobs: Default::default(),
    };
    let accept = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok());
    let mut response = match Encoding::from_accept(accept) {
        Encoding::Ssz => ssz_response(contents.to_ssz()),
        Encoding::Json => crate::json_response(serde_json::json!({
            "version": fork.as_str(),
            "execution_payload_blinded": false,
            "execution_payload_value": payload_value,
            "consensus_block_value": "0",
            "data": contents,
        })),
    };
    let headers = response.headers_mut();
    headers.insert(
        "eth-execution-payload-blinded",
        HeaderValue::from_static("false"),
    );
    if let Ok(value) = HeaderValue::from_str(&payload_value) {
        headers.insert("eth-execution-payload-value", value);
    }
    // Not computed: nothing here reads it, and the builder comparison it
    // exists for does not happen on this node.
    headers.insert("eth-consensus-block-value", HeaderValue::from_static("0"));
    with_consensus_version(response, fork)
}

/// The block for `slot`, the payload's value in wei as a decimal string, and
/// the block's fork.
async fn produce(
    store: &Store,
    engine: &EngineClient,
    pool: &SharedAttestationPool,
    fee_recipients: &FeeRecipients,
    slot: Slot,
    randao_reveal: BlsSignature,
    graffiti: Bytes32,
) -> Result<(BeaconBlock, String, ForkName), ApiError> {
    let config = store.config();
    let (head_root, head_state) = head(store)?;
    if slot <= head_state.slot() {
        return Err(ApiError::BadRequest("slot is not after the head block"));
    }
    let state = advance_to_slot(&head_state, slot, &config)
        .map_err(|_| ApiError::Internal("advancing the head state failed"))?;
    let fork = state.fork_name();
    let proposer =
        ethlambda_state_transition::beacon::helpers::accessors::get_beacon_proposer_index(&state)
            .map_err(|_| ApiError::Internal("no proposer for the slot"))?;

    let built = build_payload(store, engine, fee_recipients, &state, head_root, proposer).await?;
    if !built.blobs_bundle.commitments.is_empty() {
        warn!(%slot, blobs = built.blobs_bundle.commitments.len(), "Refusing a payload with blobs");
        return Err(ApiError::ServiceUnavailable(
            "the payload carries blobs, whose data columns this node cannot publish yet",
        ));
    }
    let execution_requests = parse_execution_requests(&built.execution_requests)
        .map_err(|_| ApiError::Internal("the execution client's request list is malformed"))?;
    let payload_value = decimal(&built.block_value);

    let candidates = pool
        .lock()
        .expect("attestation pool lock poisoned")
        .block_candidates();
    let attestations = pack_attestations(&state, candidates);
    let inputs = |attestations| BlockInputs {
        randao_reveal,
        graffiti,
        attestations,
        execution_payload: built.execution_payload.clone(),
        blob_kzg_commitments: Vec::new(),
        execution_requests: execution_requests.clone(),
    };
    let attestation_count = attestations.len();
    let block = match assemble_block(&state, inputs(attestations), &config) {
        Ok(block) => block,
        // `pack_attestations` checks every attestation's signature against this
        // state, so this should not happen; but a block without them still
        // earns the proposal, and one that fails to build earns nothing.
        Err(err) if attestation_count > 0 => {
            warn!(%slot, %err, "Block with attestations failed to build; retrying without");
            assemble_block(&state, inputs(Vec::new()), &config)
                .map_err(|_| ApiError::Internal("the block failed to build"))?
        }
        Err(_) => return Err(ApiError::Internal("the block failed to build")),
    };
    info!(
        %slot,
        proposer,
        attestations = block.body.attestations.len(),
        transactions = block.body.execution_payload.transactions.len(),
        "Produced block"
    );
    Ok((block, payload_value, fork))
}

/// Ask the execution client to build on the head for `state`'s slot, then
/// collect what it built.
///
/// Collected straight away rather than after waiting: the execution client
/// starts with a valid (possibly empty) payload and improves it, so an early
/// `getPayload` always answers, with less time for transactions to arrive. The
/// validator client asks at the start of the slot, which is when the block is
/// due.
async fn build_payload(
    store: &Store,
    engine: &EngineClient,
    fee_recipients: &FeeRecipients,
    state: &BeaconState,
    head_root: H256,
    proposer: u64,
) -> Result<BuiltPayload, ApiError> {
    let config = store.config();
    let inputs = payload_inputs(state, &config)
        .map_err(|_| ApiError::Internal("computing the payload attributes failed"))?;
    let fee_recipient = fee_recipients
        .lock()
        .expect("fee recipient lock poisoned")
        .get(&proposer)
        .copied()
        .unwrap_or_else(|| {
            warn!(
                proposer,
                "No fee recipient prepared for the proposer; using the zero address"
            );
            ExecutionAddress::ZERO
        });
    // The same rule `forkchoiceUpdated` uses for a checkpoint block (a gloas
    // one is its bid's parent hash), so the two calls never disagree.
    let forkchoice = ForkchoiceStateV1 {
        head_block_hash: inputs.parent_hash,
        safe_block_hash: ethlambda_blockchain::checkpoint_hash(
            store,
            store.beacon_justified_checkpoint().root,
        ),
        finalized_block_hash: ethlambda_blockchain::checkpoint_hash(
            store,
            store.beacon_finalized_checkpoint().root,
        ),
    };
    let attributes = PayloadAttributesV3 {
        timestamp: inputs.timestamp,
        prev_randao: inputs.prev_randao,
        suggested_fee_recipient: fee_recipient,
        withdrawals: inputs.withdrawals,
        parent_beacon_block_root: head_root,
    };
    let (status, payload_id) = engine
        .forkchoice_updated_with_attributes(&forkchoice, &attributes)
        .await
        .map_err(|err| {
            warn!(%err, "forkchoiceUpdated with payload attributes failed");
            ApiError::ServiceUnavailable("the execution client did not start building")
        })?;
    let Some(payload_id) = payload_id else {
        warn!(status = ?status.status, "The execution client declined to build a payload");
        return Err(ApiError::ServiceUnavailable(
            "the execution client declined to build a payload",
        ));
    };
    engine.get_payload(payload_id).await.map_err(|err| {
        warn!(%err, "getPayload failed");
        ApiError::ServiceUnavailable("the execution client did not return a payload")
    })
}

/// A wei amount as the decimal string the Beacon API's value fields carry.
pub(crate) fn decimal(value: &ethlambda_types::beacon::primitives::Uint256) -> String {
    let hex = uint256(value);
    u128::from_str_radix(hex.trim_start_matches("0x"), 16)
        .map(|value| value.to_string())
        .unwrap_or_else(|_| "0".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{RecordingNetwork, beacon_store_with_config};
    use axum::{body::Body, http::Request};
    use ethlambda_state_transition::beacon::helpers::test_state::with_signing_validators_at;
    use ethlambda_types::beacon::config::Config;
    use http_body_util::BodyExt as _;
    use std::sync::Arc;
    use tower::ServiceExt as _;

    /// A store holding a fulu head, under a schedule that puts every slot at
    /// gloas: the head is behind the fork, as on a node running across it.
    fn gloas_scheduled_store() -> (Store, Slot) {
        let state = with_signing_validators_at(ForkName::Fulu, 64);
        let head_slot = state.slot();
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 0);
        let (store, _root) = beacon_store_with_config(state, config);
        (store, head_slot)
    }

    async fn respond(app: Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap_or_default())
    }

    #[tokio::test]
    async fn producing_a_gloas_slot_is_a_400_even_with_no_execution_client() {
        let (store, head_slot) = gloas_scheduled_store();
        let app = routes()
            .with_state(store)
            .layer(Extension(None::<EngineClient>))
            .layer(Extension(SharedAttestationPool::default()))
            .layer(Extension(FeeRecipients::default()));
        let uri = format!(
            "/eth/v3/validator/blocks/{}?randao_reveal=0x{}",
            head_slot + 1,
            "00".repeat(96)
        );
        let (status, json) = respond(app, Request::get(uri).body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["message"], "block production is served for fulu only");
    }

    #[tokio::test]
    async fn publishing_a_fulu_body_at_a_gloas_slot_is_refused_before_advancing() {
        let (store, head_slot) = gloas_scheduled_store();
        let contents = FuluSignedBlockContents {
            signed_block: SignedBeaconBlock {
                message: BeaconBlock {
                    slot: head_slot + 1,
                    proposer_index: 0,
                    parent_root: H256::ZERO,
                    state_root: H256::ZERO,
                    body: containers::electra::BeaconBlockBody::empty(),
                },
                signature: Default::default(),
            },
            kzg_proofs: Default::default(),
            blobs: Default::default(),
        };
        let network: RpcToP2PRef = Arc::new(RecordingNetwork::default());
        let app = routes().with_state(store).layer(Extension(network));
        let request = Request::post("/eth/v2/beacon/blocks")
            .header("eth-consensus-version", "fulu")
            .header(header::CONTENT_TYPE, crate::SSZ_CONTENT_TYPE)
            .body(Body::from(contents.to_ssz()))
            .unwrap();
        let (status, json) = respond(app, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["message"], "blocks are accepted for fulu slots only");
    }

    #[tokio::test]
    async fn a_block_over_the_default_body_limit_is_not_a_413() {
        let (store, _) = gloas_scheduled_store();
        let network: RpcToP2PRef = Arc::new(RecordingNetwork::default());
        let app = routes().with_state(store).layer(Extension(network));
        let request = Request::post("/eth/v2/beacon/blocks")
            .header("eth-consensus-version", "fulu")
            .header(header::CONTENT_TYPE, crate::SSZ_CONTENT_TYPE)
            .body(Body::from(vec![0u8; 3 * 1024 * 1024]))
            .unwrap();
        let (status, _) = respond(app, request).await;
        assert_ne!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn a_signed_gloas_block_is_gossiped_and_a_forged_one_is_refused() {
        use ethlambda_state_transition::beacon::gloas_block_production::test_support::{
            config, parent_state, produce, sign_block, state_to_build_on,
        };
        let parent = parent_state();
        let state = state_to_build_on();
        let produced = produce(&state, true, Vec::new()).unwrap();
        let (mut store, _anchor) = beacon_store_with_config(parent.clone(), config());
        store
            .insert_state(produced.block.parent_root, parent)
            .unwrap();

        let signed = containers::gloas::SignedBeaconBlock {
            signature: sign_block(&state, &produced.block),
            message: produced.block.clone(),
        };
        let post = |store: Store,
                    network: Arc<RecordingNetwork>,
                    signed: &containers::gloas::SignedBeaconBlock| {
            let network: RpcToP2PRef = network;
            let app = routes().with_state(store).layer(Extension(network));
            let request = Request::post("/eth/v2/beacon/blocks")
                .header("eth-consensus-version", "gloas")
                .header(header::CONTENT_TYPE, crate::SSZ_CONTENT_TYPE)
                .body(Body::from(signed.to_ssz()))
                .unwrap();
            respond(app, request)
        };

        let network = Arc::new(RecordingNetwork::default());
        let (status, _) = post(store.clone(), network.clone(), &signed).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(network.blocks.lock().unwrap().len(), 1);

        // A signature from another validator, and a block whose parent is not held.
        let rejected = Arc::new(RecordingNetwork::default());
        let mut forged = signed.clone();
        forged.signature = sign_block(&state, &{
            let mut other = produced.block.clone();
            other.proposer_index += 1;
            other
        });
        let (status, _) = post(store.clone(), rejected.clone(), &forged).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let mut orphan = signed;
        orphan.message.parent_root = H256::repeat_byte(5);
        let (status, _) = post(store, rejected.clone(), &orphan).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(rejected.blocks.lock().unwrap().is_empty());
    }
}
