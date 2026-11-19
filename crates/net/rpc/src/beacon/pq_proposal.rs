//! PQ block production for ethlambda's own validator client.
//!
//! `POST /eth/v1/validator/pq_blocks/{slot}` takes the proposer's VRF proof
//! for the slot (its RANDAO reveal) and answers the unsigned block and the
//! unsigned envelope revealing its self-built payload, as SSZ
//! `pq::BlockContents`. The Beacon API has no PQ production endpoint yet;
//! Lighthouse's PQ branch has an equivalent of its own. The proposer signs
//! both at their own leaves and publishes them through the usual block and
//! envelope endpoints.
//!
//! The build is gloas's self-build (`gloas_proposal`) with PQ's shapes: the
//! parent's requests are PQ's, the bid carries the empty `XMSSSignature()`,
//! and the block carries no sync aggregate or payload attestations. No
//! builder bids are considered.

use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    response::{IntoResponse, Response},
    routing::post,
};
use ethlambda_blockchain::{SyncStatusController, metrics::SyncStatus};
use ethlambda_engine::EngineClient;
use ethlambda_state_transition::beacon::{
    block_production::advance_to_slot,
    fork_choice::{ForkChoiceNode, get_head_node, should_build_on_full},
    helpers::{accessors::get_beacon_proposer_index, pq::is_valid_vrf_proof},
    pq_block_production::{
        PqBlockInputs, assemble_pq_block, parse_pq_execution_requests, pq_payload_inputs,
    },
};
use ethlambda_storage::Store;
use ethlambda_types::beacon::{
    containers::{SignedBeaconBlock, SignedExecutionPayloadEnvelope, pq},
    fork::ForkName,
    primitives::{Bytes32, ExecutionAddress, Root, Slot},
    signing::compute_epoch_at_slot,
};
use libssz::SszEncode as _;
use serde::Deserialize;
use tracing::{info, warn};

use crate::CustodyColumns as NodeCustodyColumns;
use crate::beacon::{
    ApiError,
    gloas_proposal::build_payload,
    proposal::refuse_future_slot,
    validator::{FeeRecipients, head},
};
use crate::shared::content::{ssz_response, with_consensus_version};

pub(crate) fn routes() -> Router<Store> {
    Router::new().route(
        "/eth/v1/validator/pq_blocks/{slot}",
        post(post_produce_pq_block),
    )
}

#[derive(Debug, Deserialize)]
struct ProducePqBlock {
    /// The proposer's VRF proof for the slot: the leaf, then its branch.
    randao_reveal: Vec<Root>,
    #[serde(default)]
    graffiti: Option<Bytes32>,
}

async fn post_produce_pq_block(
    Path(slot): Path<String>,
    State(store): State<Store>,
    Extension(engine): Extension<Option<EngineClient>>,
    Extension(fee_recipients): Extension<FeeRecipients>,
    Extension(custody): Extension<NodeCustodyColumns>,
    Extension(sync_status): Extension<SyncStatusController>,
    Json(request): Json<ProducePqBlock>,
) -> Response {
    let Ok(slot) = slot.parse::<Slot>() else {
        return ApiError::BadRequest("invalid slot").into_response();
    };
    let config = store.config();
    if config.fork_at_epoch(compute_epoch_at_slot(slot)) != ForkName::Pq {
        return ApiError::BadRequest("this endpoint serves PQ slots only").into_response();
    }
    if let Err(err) = refuse_future_slot(&config, slot) {
        return err.into_response();
    }
    let Ok(randao_reveal) = pq::VrfProof::try_from(request.randao_reveal) else {
        return ApiError::BadRequest("randao_reveal is VRF_TREE_DEPTH + 1 roots").into_response();
    };
    if sync_status.get() == SyncStatus::Syncing {
        return ApiError::ServiceUnavailable("the node is syncing").into_response();
    }
    let Some(engine) = engine else {
        return ApiError::ServiceUnavailable(
            "no execution client configured to build a payload with",
        )
        .into_response();
    };
    match produce(
        &store,
        &engine,
        &fee_recipients,
        &custody,
        slot,
        randao_reveal,
        request.graffiti.unwrap_or(Bytes32::ZERO),
    )
    .await
    {
        Ok(contents) => with_consensus_version(ssz_response(contents.to_ssz()), ForkName::Pq),
        Err(err) => err.into_response(),
    }
}

async fn produce(
    store: &Store,
    engine: &EngineClient,
    fee_recipients: &FeeRecipients,
    custody: &NodeCustodyColumns,
    slot: Slot,
    randao_reveal: pq::VrfProof,
    graffiti: Bytes32,
) -> Result<pq::BlockContents, ApiError> {
    let config = store.config();
    let (head_root, head_state) = head(store)?;
    if slot <= head_state.slot() {
        return Err(ApiError::BadRequest("slot is not after the head block"));
    }
    let payload_status = match store.head_payload_status() {
        Some(status) => status,
        None => {
            get_head_node(store, &config)
                .map_err(|_| ApiError::Internal("fork choice could not name the head"))?
                .payload_status
        }
    };
    let node = ForkChoiceNode {
        root: head_root,
        payload_status,
    };
    let build_on_full = should_build_on_full(store, node, slot)
        .map_err(|_| ApiError::Internal("could not decide which parent payload to build on"))?;
    let head_is_pq = matches!(
        store.get_signed_block(&head_root),
        Ok(Some(SignedBeaconBlock::Pq(_)))
    );
    let parent_requests = if build_on_full && head_is_pq {
        match store
            .get_execution_payload_envelope(&head_root)
            .map_err(|_| ApiError::Internal("store read failed"))?
        {
            Some(SignedExecutionPayloadEnvelope::Pq(envelope)) => {
                envelope.message.execution_requests.clone()
            }
            Some(_) => return Err(ApiError::Internal("a PQ head with a non-PQ envelope")),
            None => {
                return Err(ApiError::ServiceUnavailable(
                    "the parent's payload envelope is not held to build on",
                ));
            }
        }
    } else {
        pq::ExecutionRequests::default()
    };

    let state = advance_to_slot(&head_state, slot, &config).map_err(|err| {
        warn!(%slot, %err, "Advancing the head state to the PQ proposal slot failed");
        ApiError::Internal("advancing the head state failed")
    })?;
    let proposer = get_beacon_proposer_index(&state)
        .map_err(|_| ApiError::Internal("no proposer for the slot"))?;
    if !is_valid_vrf_proof(&state, proposer, slot, &randao_reveal).unwrap_or(false) {
        return Err(ApiError::BadRequest("invalid randao_reveal"));
    }
    let inputs = pq_payload_inputs(&state, build_on_full, &parent_requests, &config)
        .map_err(|_| ApiError::Internal("computing the payload attributes failed"))?;
    let fee_recipient = fee_recipients
        .lock()
        .expect("fee recipient lock poisoned")
        .get(&proposer)
        .copied()
        .unwrap_or(ExecutionAddress::ZERO);
    let built = build_payload(store, engine, fee_recipient, custody, &inputs).await?;
    if !built.blobs_bundle.blobs.is_empty() {
        // The envelope's column sidecars are not built for PQ yet: a payload
        // with blobs would reveal data no node could sample.
        warn!(%slot, blobs = built.blobs_bundle.blobs.len(), "Refusing a PQ build with blobs");
        return Err(ApiError::ServiceUnavailable(
            "PQ block production does not carry blobs yet",
        ));
    }
    let execution_requests = parse_pq_execution_requests(&built.execution_requests)
        .map_err(|_| ApiError::Internal("the execution client's request list is malformed"))?;
    let produced = assemble_pq_block(
        &state,
        PqBlockInputs {
            randao_reveal,
            graffiti,
            attestations: Vec::new(),
            proof: Vec::new(),
            parent_execution_requests: parent_requests,
            execution_payload: built.execution_payload,
            blob_kzg_commitments: built.blobs_bundle.commitments,
            execution_requests,
        },
        &config,
        Default::default(),
    )
    .map_err(|err| {
        warn!(%slot, %err, "The PQ block failed to build");
        ApiError::Internal("the block failed to build")
    })?;
    info!(%slot, proposer, build_on_full, "Produced a PQ block");
    Ok(pq::BlockContents {
        block: produced.block,
        execution_payload_envelope: produced.envelope,
    })
}
