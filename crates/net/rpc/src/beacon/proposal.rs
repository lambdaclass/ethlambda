//! `GET /eth/v3/validator/blocks/{slot}` (`produceBlockV3`), a block for a
//! validator client to sign with its payload built by this node's own
//! execution client, and `POST /eth/v2/beacon/blocks` (`publishBlockV2`), the
//! signed block back to gossip and import.
//!
//! Only unblinded, locally built blocks: this node has no builder flow, so
//! `builder_boost_factor` is accepted and ignored, and every answer carries
//! `Eth-Execution-Payload-Blinded: false`.
//!
//! A payload's blobs travel with the block: production answers fulu's
//! `BlockContents` (cell proofs and blobs beside the block), and publication
//! turns the signed `SignedBlockContents` back into data column sidecars,
//! checking every cell proof first, and gossips them with the block. A
//! malformed bundle from the execution client is a 503 the validator client
//! fails over on; a block whose blobs do not verify is a 400.

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
    block_production::{
        BlockInputs, Operations, advance_to_slot, assemble_block, pack_attestations,
        pack_operations, parse_execution_requests, payload_inputs,
    },
    data_columns::{self, SidecarError},
    helpers::accessors::get_beacon_proposer_index,
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
use tracing::{error, info, warn};

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
/// Checked before it goes anywhere: the fork is fulu, its parent is a block
/// this node holds (not necessarily the head), it is after that parent, its
/// proposer is the one the parent's state advanced to its slot names, the
/// proposer's signature verifies against that state, and its blobs and cell proofs match the block's commitments and
/// verify. Then handed to P2P with the data column sidecars built from them,
/// which gossips both and gives the block to the chain actor to import. The
/// full import runs there, so `200` here means validated and broadcast, the
/// `gossip` level of `broadcast_validation`, which is the endpoint's default.
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

    let FuluSignedBlockContents {
        signed_block,
        kzg_proofs,
        blobs,
    } = contents;
    let Some(parent_state) = store
        .get_state(&signed_block.message.parent_root)
        .ok()
        .flatten()
    else {
        return ApiError::BadRequest("the block's parent is not known to this node")
            .into_response();
    };
    let config = store.config();
    let checked = tokio::task::spawn_blocking(move || {
        let slot = signed_block.message.slot;
        if slot <= parent_state.slot() {
            return Err(("the block is not after its parent", None));
        }
        let state = advance_to_slot(&parent_state, slot, &config)
            .map_err(|_| ("advancing the parent state failed", None))?;
        let proposer =
            get_beacon_proposer_index(&state).map_err(|_| ("no proposer for the slot", None))?;
        if signed_block.message.proposer_index != proposer {
            return Err(("wrong proposer for the slot", None));
        }
        let block = containers::SignedBeaconBlock::Fulu(signed_block);
        if !verify_block_signature(&state, &block) {
            return Err(("invalid block signature", None));
        }
        let containers::SignedBeaconBlock::Fulu(signed_block) = block else {
            unreachable!("the block was wrapped as fulu above");
        };
        // Without blobs there is no KZG work, and the metric would only be
        // diluted by free samples.
        if signed_block.message.body.blob_kzg_commitments.is_empty() && blobs.is_empty() {
            return Ok((signed_block, Vec::new(), None));
        }
        let started = std::time::Instant::now();
        let sidecars = data_columns::verified_sidecars(&signed_block, &blobs, &kzg_proofs)
            .map_err(|err| {
                let message = match err {
                    SidecarError::Shape(_) => {
                        "the block's blobs and cell proofs do not match its commitments"
                    }
                    SidecarError::InvalidBlob => "a blob is not a valid polynomial evaluation",
                    SidecarError::InvalidProofs => "the cell proofs do not verify",
                };
                (message, Some((slot, err)))
            })?;
        Ok((signed_block, sidecars, Some(started.elapsed())))
    })
    .await;
    let (signed_block, sidecars) = match checked {
        Ok(Ok((signed_block, sidecars, elapsed))) => {
            if let Some(elapsed) = elapsed {
                crate::metrics::observe_publish_data_columns(elapsed);
            }
            (signed_block, sidecars)
        }
        Ok(Err((message, detail))) => {
            if let Some((slot, err)) = detail {
                warn!(slot, %err, "Refusing a published block's blobs");
            }
            return ApiError::BadRequest(message).into_response();
        }
        Err(err) => {
            error!(%err, "Checking a published block failed");
            return ApiError::Internal("building the data column sidecars failed").into_response();
        }
    };
    let block = containers::SignedBeaconBlock::Fulu(signed_block);
    if p2p.publish_beacon_block(block, sidecars).is_err() {
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
        &fee_recipients,
        slot,
        query.randao_reveal,
        graffiti,
    )
    .await;
    let (contents, payload_value, fork) = match produced {
        Ok(produced) => produced,
        Err(err) => return err.into_response(),
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

/// The block for `slot` with its blobs and cell proofs, the payload's value in
/// wei as a decimal string, and the block's fork.
async fn produce(
    store: &Store,
    engine: &EngineClient,
    fee_recipients: &FeeRecipients,
    slot: Slot,
    randao_reveal: BlsSignature,
    graffiti: Bytes32,
) -> Result<(FuluBlockContents, String, ForkName), ApiError> {
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

    let mut built =
        build_payload(store, engine, fee_recipients, &state, head_root, proposer).await?;
    let bundle = &built.blobs_bundle;
    let malformed = bundle.commitments.len() != bundle.blobs.len()
        || bundle.proofs.len() != bundle.blobs.len() * preset::CELLS_PER_EXT_BLOB;
    if malformed {
        warn!(
            %slot,
            commitments = bundle.commitments.len(),
            proofs = bundle.proofs.len(),
            blobs = bundle.blobs.len(),
            "The execution client's blobs bundle is malformed"
        );
        return Err(ApiError::ServiceUnavailable(
            "the execution client's blobs bundle is malformed",
        ));
    }
    // The proofs are not verified here: the payload's blob transactions fix
    // its commitments, so a bad proof has no other block to fall back to. The
    // check at publication is the gate.
    let blobs = std::mem::take(&mut built.blobs_bundle.blobs)
        .into_iter()
        .map(|blob| Blob::try_from(blob).ok())
        .collect::<Option<Vec<_>>>()
        .and_then(|blobs| Blobs::try_from(blobs).ok());
    let kzg_proofs = CellKzgProofs::try_from(std::mem::take(&mut built.blobs_bundle.proofs)).ok();
    let (Some(blobs), Some(kzg_proofs)) = (blobs, kzg_proofs) else {
        warn!(%slot, "The execution client's blobs do not fit their containers");
        return Err(ApiError::ServiceUnavailable(
            "the execution client's blobs bundle is malformed",
        ));
    };
    let execution_requests = parse_execution_requests(&built.execution_requests)
        .map_err(|_| ApiError::Internal("the execution client's request list is malformed"))?;
    let payload_value = decimal(&built.block_value);

    let candidates = store.attestation_pool().block_candidates();
    let attestations = pack_attestations(&state, candidates);
    let operation_candidates = {
        let pool = store.operation_pool();
        Operations {
            proposer_slashings: pool.proposer_slashings(),
            attester_slashings: pool.attester_slashings(),
            voluntary_exits: pool.voluntary_exits(),
            bls_to_execution_changes: pool.bls_to_execution_changes(),
        }
    };
    let operations = pack_operations(&state, operation_candidates, &config);
    let inputs = |attestations, operations| BlockInputs {
        randao_reveal,
        graffiti,
        attestations,
        operations,
        execution_payload: built.execution_payload.clone(),
        blob_kzg_commitments: built.blobs_bundle.commitments.clone(),
        execution_requests: execution_requests.clone(),
    };
    let attestation_count = attestations.len();
    let has_operations = !operations.is_empty();
    let block = match assemble_block(&state, inputs(attestations, operations), &config) {
        Ok(block) => block,
        // `pack_attestations` and `pack_operations` check every candidate
        // against this state, so this should not happen; but a block without
        // them still earns the proposal, and one that fails to build earns
        // nothing.
        Err(err) if attestation_count > 0 || has_operations => {
            warn!(%slot, %err, "Block with attestations or operations failed to build; retrying without");
            assemble_block(&state, inputs(Vec::new(), Operations::default()), &config)
                .map_err(|_| ApiError::Internal("the block failed to build"))?
        }
        Err(_) => return Err(ApiError::Internal("the block failed to build")),
    };
    info!(
        %slot,
        proposer,
        attestations = block.body.attestations.len(),
        slashings = block.body.proposer_slashings.len() + block.body.attester_slashings.len(),
        exits = block.body.voluntary_exits.len(),
        bls_changes = block.body.bls_to_execution_changes.len(),
        transactions = block.body.execution_payload.transactions.len(),
        blobs = block.body.blob_kzg_commitments.len(),
        "Produced block"
    );
    let contents = FuluBlockContents {
        block,
        kzg_proofs,
        blobs,
    };
    Ok((contents, payload_value, fork))
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
