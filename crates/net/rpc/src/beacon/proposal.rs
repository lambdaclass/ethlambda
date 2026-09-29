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
    extract::{Path, Query, State},
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
        containers::{
            self, BeaconState,
            deneb::Blob,
            electra::{BeaconBlock, SignedBeaconBlock},
        },
        fork::ForkName,
        preset,
        primitives::{BlsSignature, Bytes32, ExecutionAddress, KzgProof, Slot},
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
        .route("/eth/v2/beacon/blocks", post(post_block))
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
    if fork != Some(ForkName::Fulu) {
        return ApiError::BadRequest("Eth-Consensus-Version must be fulu").into_response();
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

#[derive(Debug, Deserialize)]
struct ProduceQuery {
    randao_reveal: BlsSignature,
    #[serde(default)]
    graffiti: Option<H256>,
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
    if fork != ForkName::Fulu {
        return Err(ApiError::BadRequest(
            "block production is served for fulu only",
        ));
    }
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
    let el_hash = |root: H256| store.beacon_el_block_hash(root).unwrap_or(H256::ZERO);
    let forkchoice = ForkchoiceStateV1 {
        head_block_hash: inputs.parent_hash,
        safe_block_hash: el_hash(store.beacon_justified_checkpoint().root),
        finalized_block_hash: el_hash(store.beacon_finalized_checkpoint().root),
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
fn decimal(value: &ethlambda_types::beacon::primitives::Uint256) -> String {
    let hex = uint256(value);
    u128::from_str_radix(hex.trim_start_matches("0x"), 16)
        .map(|value| value.to_string())
        .unwrap_or_else(|_| "0".to_string())
}
