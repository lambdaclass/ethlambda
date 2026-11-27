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
//! builder bids are considered. The graffiti gets both clients' version codes
//! appended, as every other block this node builds does.
//!
//! The attestations come from the pool of validated network aggregates, and
//! their proofs are merged into the block's one `proof`. The chain actor does
//! that ahead of the slot, alongside the payload build, for the slots this
//! node's proposers hold, and production collects it when it was for the head
//! it builds on (`ethlambda_blockchain::pq_attestation_packing`); otherwise
//! it merges here while the execution client builds the payload. A merge is a
//! leanVM proof, in process, and costs from under a second to seconds when
//! there is more than one child, so it is bounded by a deadline three quarters
//! of the way to the slot's attestation deadline (Lighthouse's PQ branch uses
//! the same one). A merge that misses it or fails is dropped for the most
//! valuable single-committee attestation alone, whose proof needs no merging;
//! a block `process_stark` refuses is built again without attestations, so the
//! block goes out rather than not at all.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    response::{IntoResponse, Response},
    routing::post,
};
use ethlambda_blockchain::{
    PreparedPayloads, PreparedPqAttestations, SyncStatusController,
    metrics::SyncStatus,
    payload_attributes::{PqProposal, ProposalError, prepare_pq_proposal, prepared_fee_recipient},
    pq_attestation_packing::{PermitWait, merge_budget, pack_attestations},
};
use ethlambda_engine::{EngineClient, types::ClientVersionV1};
use ethlambda_state_transition::beacon::{
    helpers::pq::is_valid_vrf_proof,
    pq_block_production::{PqBlockInputs, assemble_pq_block, parse_pq_execution_requests},
};
use ethlambda_storage::Store;
use ethlambda_types::beacon::{
    config::Config,
    containers::{BeaconState, pq},
    fork::ForkName,
    primitives::{Bytes32, ExecutionAddress, HashTreeRoot as _, KzgProof, Root, Slot},
    signing::compute_epoch_at_slot,
};
use libssz::SszEncode as _;
use serde::Deserialize;
use tracing::{info, warn};

use crate::CustodyColumns as NodeCustodyColumns;
use crate::beacon::{
    ApiError,
    gloas_proposal::build_payload,
    graffiti::{self, OwnVersion},
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

/// The blobs and cell proofs of the PQ payloads this node built, by
/// `(slot, block root)`, for the current and previous slot.
///
/// This endpoint hands the validator client the block and the unsigned
/// envelope only, and the client publishes the signed envelope through
/// `publishExecutionPayloadEnvelope` without blobs, so that endpoint builds
/// the envelope's data columns from what is kept here (gloas's
/// `Eth-Blob-Data-Included: false` path, which reads `produceBlockV4`'s own
/// cache). Shared through an extension both routers carry.
#[derive(Debug, Clone, Default)]
pub(crate) struct PqBlobs(Arc<Mutex<BTreeMap<(Slot, Root), PqPayloadBlobs>>>);

/// One PQ payload's blobs and their cell proofs, as the execution client
/// returned them.
#[derive(Debug, Clone, Default)]
pub(crate) struct PqPayloadBlobs {
    pub(crate) blobs: Vec<Vec<u8>>,
    pub(crate) cell_proofs: Vec<KzgProof>,
}

impl PqBlobs {
    fn insert(&self, slot: Slot, block_root: Root, blobs: PqPayloadBlobs) {
        let mut entries = self.0.lock().expect("PQ blob cache lock poisoned");
        entries.insert((slot, block_root), blobs);
        let keep_from = slot.saturating_sub(1);
        entries.retain(|(held, _), _| *held >= keep_from);
    }

    pub(crate) fn get(&self, slot: Slot, block_root: Root) -> Option<PqPayloadBlobs> {
        self.0
            .lock()
            .expect("PQ blob cache lock poisoned")
            .get(&(slot, block_root))
            .cloned()
    }
}

#[derive(Debug, Deserialize)]
struct ProducePqBlock {
    /// The proposer's VRF proof for the slot: the secret, then its leaf's
    /// branch.
    randao_reveal: Vec<Root>,
    #[serde(default)]
    graffiti: Option<Bytes32>,
}

#[expect(clippy::too_many_arguments)]
async fn post_produce_pq_block(
    Path(slot): Path<String>,
    State(store): State<Store>,
    Extension(engine): Extension<Option<EngineClient>>,
    Extension(fee_recipients): Extension<FeeRecipients>,
    Extension(custody): Extension<NodeCustodyColumns>,
    Extension(OwnVersion(own_version)): Extension<OwnVersion>,
    Extension(sync_status): Extension<SyncStatusController>,
    blob_cache: Option<Extension<PqBlobs>>,
    ahead: Option<Extension<PreparedPayloads>>,
    ahead_attestations: Option<Extension<PreparedPqAttestations>>,
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
        ahead.as_ref().map(|Extension(ahead)| ahead),
        ahead_attestations.as_ref().map(|Extension(ahead)| ahead),
        &own_version,
        slot,
        randao_reveal,
        request.graffiti.unwrap_or(Bytes32::ZERO),
    )
    .await
    {
        Ok((contents, blobs)) => {
            if !blobs.blobs.is_empty() {
                // Without the cache the envelope cannot carry its columns, so
                // a block committing to blobs must not go out.
                let Some(Extension(cache)) = blob_cache else {
                    return ApiError::Internal("no blob cache to publish the payload's blobs from")
                        .into_response();
                };
                cache.insert(slot, contents.block.hash_tree_root(), blobs);
            }
            with_consensus_version(ssz_response(contents.to_ssz()), ForkName::Pq)
        }
        Err(err) => err.into_response(),
    }
}

#[expect(clippy::too_many_arguments)]
async fn produce(
    store: &Store,
    engine: &EngineClient,
    fee_recipients: &FeeRecipients,
    custody: &NodeCustodyColumns,
    ahead: Option<&PreparedPayloads>,
    ahead_attestations: Option<&PreparedPqAttestations>,
    own_version: &ClientVersionV1,
    slot: Slot,
    randao_reveal: pq::VrfProof,
    graffiti: Bytes32,
) -> Result<(pq::BlockContents, PqPayloadBlobs), ApiError> {
    let config = store.config();
    let (head_root, head_state) = head(store)?;
    // The same preparation the chain actor starts the payload build ahead of
    // the slot with, so the two ask for the same attributes.
    let PqProposal {
        state,
        inputs,
        proposer,
        build_on_full,
        parent_requests,
    } = prepare_pq_proposal(store, head_root, &head_state, slot).map_err(|err| match err {
        ProposalError::NotAfterHead => ApiError::BadRequest("slot is not after the head block"),
        ProposalError::ParentEnvelopeMissing => {
            ApiError::ServiceUnavailable("the parent's payload envelope is not held to build on")
        }
        ProposalError::Internal(message) => ApiError::Internal(message),
    })?;
    if !is_valid_vrf_proof(&state, proposer, slot, &randao_reveal).unwrap_or(false) {
        return Err(ApiError::BadRequest("invalid randao_reveal"));
    }
    let fee_recipient =
        prepared_fee_recipient(fee_recipients, proposer).unwrap_or(ExecutionAddress::ZERO);
    // The execution client's version, for the graffiti, is asked alongside
    // the build, as gloas's production does.
    let (built, (attestations, proof), el_version) = tokio::join!(
        build_payload(store, engine, fee_recipient, custody, &inputs, ahead),
        attestations_for_block(store, &state, &config, head_root, ahead_attestations),
        graffiti::execution_client_version(engine, own_version),
    );
    let graffiti = graffiti::with_client_versions(graffiti, el_version.as_ref(), own_version);
    let built = built?;
    let bundle = &built.blobs_bundle;
    if bundle.commitments.len() != bundle.blobs.len()
        || bundle.proofs.len()
            != bundle.blobs.len() * ethlambda_types::beacon::preset::CELLS_PER_EXT_BLOB
    {
        warn!(%slot, "The execution client's blobs bundle is inconsistent");
        return Err(ApiError::ServiceUnavailable(
            "the execution client returned an inconsistent blobs bundle",
        ));
    }
    // Kept for the envelope endpoint, which builds the data columns from
    // them (see [`PqBlobs`]).
    let blobs = PqPayloadBlobs {
        blobs: built.blobs_bundle.blobs.clone(),
        cell_proofs: built.blobs_bundle.proofs.clone(),
    };
    let execution_requests = parse_pq_execution_requests(&built.execution_requests)
        .map_err(|_| ApiError::Internal("the execution client's request list is malformed"))?;
    let inputs = PqBlockInputs {
        randao_reveal,
        graffiti,
        attestations,
        proof,
        parent_execution_requests: parent_requests,
        execution_payload: built.execution_payload,
        blob_kzg_commitments: built.blobs_bundle.commitments,
        execution_requests,
    };
    // `process_block` runs `process_stark` on the merged proof: one that does
    // not prove the packed attestations fails here, and the block is built
    // again without them.
    let fallback = (!inputs.attestations.is_empty()).then(|| PqBlockInputs {
        attestations: Vec::new(),
        proof: Vec::new(),
        ..inputs.clone()
    });
    let produced = match assemble_pq_block(&state, inputs, &config, Default::default()) {
        Ok(produced) => produced,
        Err(err) => {
            let Some(fallback) = fallback else {
                warn!(%slot, %err, "The PQ block failed to build");
                return Err(ApiError::Internal("the block failed to build"));
            };
            warn!(%slot, %err, "The PQ block failed to build with its attestations; building it without");
            assemble_pq_block(&state, fallback, &config, Default::default()).map_err(|err| {
                warn!(%slot, %err, "The PQ block failed to build");
                ApiError::Internal("the block failed to build")
            })?
        }
    };
    let attestations = produced.block.body.attestations.len();
    let graffiti = graffiti::display(&produced.block.body.graffiti);
    info!(%slot, proposer, build_on_full, attestations, %graffiti, "Produced a PQ block");
    let contents = pq::BlockContents {
        block: produced.block,
        execution_payload_envelope: produced.envelope,
    };
    Ok((contents, blobs))
}

/// The attestations a PQ block at `state`'s slot packs and the merged proof
/// of their aggregates: the ones the chain actor packed ahead of the slot for
/// this head when it did, and otherwise packed now
/// (`ethlambda_blockchain::pq_attestation_packing`).
async fn attestations_for_block(
    store: &Store,
    state: &BeaconState,
    config: &Config,
    head_root: Root,
    prepared: Option<&PreparedPqAttestations>,
) -> (Vec<pq::Attestation>, Vec<u8>) {
    let slot = state.slot();
    if let Some(prepared) = prepared {
        // The whole merge budget: a packing under way for this slot and head
        // computes what production would, and holds the one merge permit
        // production would need, so production could not do better by
        // giving up on it early. One that ends partial or stale still leaves
        // production whatever time is left, with the permit free.
        let budget = merge_budget(config, slot).unwrap_or_default();
        if let Some(packed) = prepared.take(store, slot, head_root, budget).await {
            info!(
                %slot,
                attestations = packed.attestations.len(),
                proof_bytes = packed.proof.len(),
                "Collected the PQ attestations packed ahead of the slot"
            );
            return (packed.attestations, packed.proof);
        }
    }
    let packed = pack_attestations(store, state, config, PermitWait::TryOnce).await;
    (packed.attestations, packed.proof)
}
