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
//! their proofs are merged into the block's one `proof` while the execution
//! client builds the payload. A merge runs on the proving sidecar and costs
//! seconds when there is more than one child, so it is bounded by a deadline
//! three quarters of the way to the slot's attestation deadline (Lighthouse's
//! PQ branch uses the same one). A merge that misses it or fails is dropped
//! for the most valuable single-committee attestation alone, whose proof
//! needs no merging; a block `process_stark` refuses is built again without
//! attestations, so the block goes out rather than not at all.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    response::{IntoResponse, Response},
    routing::post,
};
use ethlambda_blockchain::{SyncStatusController, metrics::SyncStatus};
use ethlambda_engine::{EngineClient, types::ClientVersionV1};
use ethlambda_state_transition::beacon::{
    block_production::advance_to_slot,
    fork_choice::{ForkChoiceNode, get_attestation_due_ms, get_head_node, should_build_on_full},
    helpers::{accessors::get_beacon_proposer_index, pq::is_valid_vrf_proof},
    pq_block_production::{
        PqBlockInputs, PqPacked, assemble_pq_block, parse_pq_execution_requests, pq_payload_inputs,
        select_pq_attestations,
    },
};
use ethlambda_storage::Store;
use ethlambda_types::beacon::{
    config::Config,
    containers::{BeaconState, SignedBeaconBlock, SignedExecutionPayloadEnvelope, pq},
    fork::ForkName,
    preset::MIN_ATTESTATION_INCLUSION_DELAY_PQ,
    primitives::{Bytes32, ExecutionAddress, HashTreeRoot as _, KzgProof, Root, Slot},
    signing::compute_epoch_at_slot,
};
use libssz::SszEncode as _;
use serde::Deserialize;
use tokio::sync::Semaphore;
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
    /// The proposer's VRF proof for the slot: the leaf, then its branch.
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
    own_version: &ClientVersionV1,
    slot: Slot,
    randao_reveal: pq::VrfProof,
    graffiti: Bytes32,
) -> Result<(pq::BlockContents, PqPayloadBlobs), ApiError> {
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
    // The execution client's version, for the graffiti, is asked alongside
    // the build, as gloas's production does.
    let (built, (attestations, proof), el_version) = tokio::join!(
        build_payload(store, engine, fee_recipient, custody, &inputs),
        pack_attestations(store, &state, &config),
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

/// One merge at a time: the sidecar proves one request after another, so a
/// second merge started while one runs would only push both past their
/// deadlines. A merge that missed its deadline keeps the permit until it
/// ends.
static MERGE_PERMIT: Semaphore = Semaphore::const_new(1);

/// The attestations a PQ block at `state`'s slot packs and the merged proof
/// of their aggregates, or none when there are none, the merge misses its
/// deadline, or it fails.
async fn pack_attestations(
    store: &Store,
    state: &BeaconState,
    config: &Config,
) -> (Vec<pq::Attestation>, Vec<u8>) {
    let slot = state.slot();
    let latest = slot.saturating_sub(MIN_ATTESTATION_INCLUSION_DELAY_PQ);
    let candidates = store.pq_aggregate_pool().candidates(latest);
    if candidates.is_empty() {
        return Default::default();
    }
    let selected = {
        let (store, state) = (store.clone(), state.clone());
        tokio::task::spawn_blocking(move || {
            select_pq_attestations(&state, candidates, &store.committee_cache())
        })
        .await
    };
    let packed = match selected {
        Ok(Ok(packed)) => packed,
        Ok(Err(err)) => {
            warn!(%slot, %err, "Selecting the PQ attestations failed");
            return Default::default();
        }
        Err(err) => {
            warn!(%slot, %err, "The PQ attestation selection task failed");
            return Default::default();
        }
    };
    if packed.attestations.is_empty() {
        return Default::default();
    }
    // One child's proof is the block's as it is; more must be merged.
    let fallback = packed.first_unmerged();
    if packed.children.len() == 1 {
        return unmerged(slot, packed);
    }
    let children = packed.children.len();
    let fall_back = |reason: &str| {
        warn!(%slot, children, reason, "Packing one PQ attestation instead of merging every proof");
        fallback
            .clone()
            .map_or_else(Default::default, |single| unmerged(slot, single))
    };
    let Some(remaining) = merge_budget(config, slot) else {
        return fall_back("no time left to merge");
    };
    let Ok(permit) = MERGE_PERMIT.try_acquire() else {
        return fall_back("a merge is still running");
    };
    let budget_ms = remaining.as_millis() as u64;
    let job = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let started = Instant::now();
        let proof = packed.merge().map_err(|err| err.to_string());
        // Logged when it ends, deadline or not: what a merge costs here, how
        // big it was and how much of the budget it used.
        let signatures: usize = packed
            .children
            .iter()
            .flat_map(|(statements, _)| statements)
            .map(|statement| statement.pubkeys.len())
            .sum();
        info!(
            %slot,
            attestations = packed.attestations.len(),
            children,
            signatures,
            proof_bytes = proof.as_ref().map_or(0, Vec::len),
            took_ms = started.elapsed().as_millis() as u64,
            budget_ms,
            ok = proof.is_ok(),
            "Merged PQ attestation proofs"
        );
        proof.map(|proof| (packed, proof))
    });
    match tokio::time::timeout(remaining, job).await {
        Ok(Ok(Ok((packed, proof)))) => {
            info!(
                %slot,
                attestations = packed.attestations.len(),
                children,
                proof_bytes = proof.len(),
                "Packed PQ attestations"
            );
            (packed.attestations, proof)
        }
        Ok(Ok(Err(err))) => fall_back(&format!("the merge failed: {err}")),
        Ok(Err(err)) => fall_back(&format!("the merge task failed: {err}")),
        Err(_) => fall_back(&format!(
            "the merge missed its {} ms budget",
            remaining.as_millis()
        )),
    }
}

/// `packed` with its one child's proof as the block's, nothing merged.
fn unmerged(slot: Slot, packed: PqPacked) -> (Vec<pq::Attestation>, Vec<u8>) {
    match packed.merge() {
        Ok(proof) => {
            info!(
                %slot,
                attestations = packed.attestations.len(),
                proof_bytes = proof.len(),
                "Packed PQ attestations"
            );
            (packed.attestations, proof)
        }
        Err(err) => {
            warn!(%slot, %err, "A single PQ proof would not pass through the merge");
            Default::default()
        }
    }
}

/// How long a merge for a block at `slot` may take: until three quarters of
/// the slot's attestation deadline, so the block still reaches the attesters
/// in time. `None` once that point has passed.
fn merge_budget(config: &Config, slot: Slot) -> Option<Duration> {
    let due_ms = get_attestation_due_ms(compute_epoch_at_slot(slot), config);
    let deadline_ms = config
        .genesis_time
        .saturating_mul(1000)
        .saturating_add(slot.saturating_mul(config.slot_duration_ms))
        .saturating_add(due_ms.saturating_mul(3) / 4);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64);
    deadline_ms
        .checked_sub(now_ms)
        .filter(|&left| left > 0)
        .map(Duration::from_millis)
}
