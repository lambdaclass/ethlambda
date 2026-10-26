//! `GET /eth/v3/validator/blocks/{slot}` (`produceBlockV3`), a block for a
//! validator client to sign with its payload built by this node's own
//! execution client, and `POST /eth/v2/beacon/blocks` (`publishBlockV2`), the
//! signed block back to gossip and import.
//!
//! Locally built blocks, or, with `--builder` set and a builder's bid that
//! validates and beats the local payload under `builder_boost_factor`, the
//! blinded block around that bid. Every answer says which in
//! `Eth-Execution-Payload-Blinded`.
//!
//! A payload's blobs travel with the block: production answers fulu's
//! `BlockContents` (cell proofs and blobs beside the block), and publication
//! turns the signed `SignedBlockContents` back into data column sidecars,
//! checking every cell proof first, and gossips them with the block. A
//! malformed bundle from the execution client is a 503 the validator client
//! fails over on; a block whose blobs do not verify is a 400.
//!
//! The validator client's graffiti gets this node's and its execution client's
//! versions appended, always; see [`super::graffiti`].

use axum::{
    Extension, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ethlambda_blockchain::metrics::SyncStatus;
use ethlambda_engine::{
    EngineClient, ForkchoiceStateV1,
    building::{BuiltPayload, PayloadAttributesV3},
    types::{ClientVersionV1, uint256},
};
use ethlambda_network_api::RpcToP2PRef;
use ethlambda_state_transition::beacon::{
    block_production::{
        BlindedBlockInputs, BlockInputs, Operations, advance_to_slot, assemble_blinded_block,
        assemble_block, empty_sync_aggregate, pack_attestations, pack_operations,
        parse_execution_requests, payload_inputs, verified_sync_aggregate,
    },
    bls,
    data_columns::{self, SidecarError},
    helpers::accessors::get_beacon_proposer_index,
    stf::{
        block::{BlockProcessingOptions, RandaoVerification},
        verify_block_signature,
    },
    sync_committee_pool::SharedSyncCommitteePool,
};
use ethlambda_storage::Store;
use ethlambda_types::{
    beacon::{
        builder::{BlindedBeaconBlock, BuilderBid, ValidatorRegistrationV1},
        config::Config,
        containers::{
            self, BeaconState,
            altair::SyncAggregate,
            deneb::Blob,
            electra::{Attestation, BeaconBlock, ExecutionRequests, SignedBeaconBlock},
        },
        fork::ForkName,
        preset,
        primitives::{
            BlsPubkey, BlsSignature, Bytes32, ExecutionAddress, ExecutionBlockHash,
            HashTreeRoot as _, KzgProof, Slot, Uint256, ValidatorIndex,
        },
        signing::compute_epoch_at_slot,
    },
    primitives::H256,
};
use libssz::SszEncode as _;
use libssz_derive::{SszDecode, SszEncode};
use libssz_types::SszList;
use serde::Deserialize;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::beacon::bid_selection::wei_u128;
use crate::beacon::blinded_blocks::{self, PublishedProposals, finalized_slot};
use crate::beacon::builder_client::VersionedBid;
use crate::beacon::builder_flow::{
    Builder,
    bid::{self, BidContext},
    breaker,
    choice::{self, DEFAULT_BOOST_FACTOR, LocalOffer, Source},
};
use crate::beacon::graffiti::{self, OwnVersion};
use crate::beacon::{ApiError, BodyEncoding, validator::FeeRecipients, validator::head};
use crate::metrics::{inc_bid_rejection, inc_builder_fallback, inc_payload_source};
use crate::shared::content::{Encoding, ssz_response, with_consensus_version};
use crate::shared::optimistic::block_is_optimistic;

/// One KZG proof per cell of every blob, fulu's `kzg_proofs` bound.
pub(crate) type CellKzgProofs = SszList<
    KzgProof,
    { preset::FIELD_ELEMENTS_PER_EXT_BLOB * preset::MAX_BLOB_COMMITMENTS_PER_BLOCK },
>;
pub(crate) type Blobs = SszList<Blob, { preset::MAX_BLOB_COMMITMENTS_PER_BLOCK }>;

/// Fulu's `BlockContents`, the Beacon API's envelope for an unblinded block
/// and the blobs its proposer publishes with it. A beacon-APIs container, not
/// a consensus one, so it lives with the API.
#[derive(Debug, Clone, PartialEq, SszEncode, SszDecode, serde::Serialize, serde::Deserialize)]
pub(crate) struct FuluBlockContents {
    pub(crate) block: BeaconBlock,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::seq")]
    pub(crate) kzg_proofs: CellKzgProofs,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::ssz_hex_seq")]
    pub(crate) blobs: Blobs,
}

/// Fulu's `SignedBlockContents`, what `publishBlockV2` receives.
#[derive(Debug, Clone, PartialEq, SszEncode, SszDecode, serde::Serialize, serde::Deserialize)]
pub(crate) struct FuluSignedBlockContents {
    pub(crate) signed_block: SignedBeaconBlock,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::seq")]
    pub(crate) kzg_proofs: CellKzgProofs,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::ssz_hex_seq")]
    pub(crate) blobs: Blobs,
}

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route("/eth/v3/validator/blocks/{slot}", get(get_block))
        .route(
            "/eth/v2/beacon/blocks",
            post(post_block).layer(DefaultBodyLimit::max(super::MAX_PUBLISH_BODY_BYTES)),
        )
        .route(
            "/eth/v2/beacon/blinded_blocks",
            post(blinded_blocks::post_blinded_block)
                .layer(DefaultBodyLimit::max(super::MAX_PUBLISH_BODY_BYTES)),
        )
        .layer(Extension(PublishedProposals::default()))
}

/// `POST /eth/v2/beacon/blocks`, `SignedBlockContents` (fulu) or a bare
/// `SignedBeaconBlock` (gloas), as SSZ or JSON by `Content-Type`.
///
/// Checked before it goes anywhere: the fork is fulu (both the header and the
/// slot's place in the schedule), its parent is a block this node holds (not
/// necessarily the head), it is after that parent, its proposer is the one the
/// parent's state advanced to its slot names, the proposer's signature
/// verifies against that state, and its blobs and cell proofs match the
/// block's commitments and verify. Then handed to P2P with the data column
/// sidecars built from them,
/// which gossips both and gives the block to the chain actor to import. The
/// full import runs there, so `200` here means validated and broadcast, the
/// `gossip` level of `broadcast_validation`, which is the endpoint's default.
async fn post_block(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    Extension(published): Extension<PublishedProposals>,
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
    let encoding = match BodyEncoding::from_headers(&headers) {
        Ok(encoding) => encoding,
        Err(err) => return err.into_response(),
    };
    if fork == Some(ForkName::Gloas) {
        return post_gloas_block(&store, &p2p, &published, encoding, &body).await;
    }
    let Some(contents) = encoding.decode::<FuluSignedBlockContents>(&body) else {
        return ApiError::BadRequest("the body is not fulu SignedBlockContents").into_response();
    };
    // Before the parent's state is advanced: a fulu body at a gloas slot would
    // run `upgrade_to_gloas` only to be refused afterwards.
    if let Err(err) = require_fulu_slot(
        &store.config(),
        contents.signed_block.message.slot,
        "blocks are accepted for fulu slots only",
    ) {
        return err.into_response();
    }

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
    let root = signed_block.message.hash_tree_root();
    let slot = signed_block.message.slot;
    if let Err(err) = published.claim(slot, root, finalized_slot(&store)) {
        warn!(slot, ?err, "Refusing a block for the slot");
        return err.into_api_error().into_response();
    }
    let block = containers::SignedBeaconBlock::Fulu(signed_block);
    let sidecars = sidecars
        .into_iter()
        .map(containers::DataColumnSidecar::Fulu)
        .collect();
    if p2p.publish_beacon_block(block, sidecars).is_err() {
        return ApiError::Internal("the network actor is not running").into_response();
    }
    StatusCode::OK.into_response()
}

/// The gloas half of `publishBlockV2`: a bare `SignedBeaconBlock`, since a
/// gloas block carries no payload and no blobs of its own (the envelope and
/// the data columns follow through `publishExecutionPayloadEnvelope`).
///
/// Checked as the fulu one is, before it goes anywhere: the parent is held,
/// the slot is after the parent's and scheduled at gloas, the proposer is the
/// slot's, and the proposer's signature verifies against the parent's state
/// advanced to the slot. The advance and the signature are CPU-bound and run
/// off the runtime.
async fn post_gloas_block(
    store: &Store,
    p2p: &RpcToP2PRef,
    published: &PublishedProposals,
    encoding: BodyEncoding,
    body: &[u8],
) -> Response {
    let Some(signed) = encoding.decode::<containers::gloas::SignedBeaconBlock>(body) else {
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
    let slot = block.slot();
    let root = block.message_hash_tree_root();
    if let Err(err) = published.claim(slot, root, finalized_slot(store)) {
        warn!(slot, ?err, "Refusing a block for the slot");
        return err.into_api_error().into_response();
    }
    // A gloas block carries no blobs of its own: its data columns travel with
    // the execution payload envelope, published separately, so there are no
    // sidecars to gossip with the block.
    if p2p.publish_beacon_block(block, Vec::new()).is_err() {
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
    /// A flag with no value, validated by [`randao_verification`].
    #[serde(default)]
    skip_randao_verification: Option<String>,
    /// beacon-APIs' weight on the builder's bid, in percent; absent is 100.
    #[serde(default)]
    builder_boost_factor: Option<u64>,
}

/// Whether the block's RANDAO reveal is verified, from the request's
/// `skip_randao_verification` flag, the way Lighthouse reads it.
///
/// The flag takes no value, so `?skip_randao_verification` and
/// `?skip_randao_verification=` set it and any other value is refused rather
/// than guessed at. Skipping is only for a reveal that cannot verify against
/// any key (`bls::G2_POINT_AT_INFINITY`), so a caller that sets the flag with a
/// real reveal has misunderstood it, and the block would otherwise be produced
/// against a reveal that was never checked.
pub(super) fn randao_verification(
    skip: Option<&str>,
    randao_reveal: &BlsSignature,
) -> Result<RandaoVerification, ApiError> {
    match skip {
        None => Ok(RandaoVerification::Verify),
        Some("") => {
            if randao_reveal.0 == bls::G2_POINT_AT_INFINITY {
                Ok(RandaoVerification::Skip)
            } else {
                Err(ApiError::BadRequest(
                    "randao_reveal must be the point at infinity when skip_randao_verification is set",
                ))
            }
        }
        Some(_) => Err(ApiError::BadRequest(
            "skip_randao_verification does not take a value",
        )),
    }
}

/// Refuses a slot the schedule does not place at fulu, before anything
/// advances a state to it: advancing a fulu head into a gloas slot would run
/// `upgrade_to_gloas` only to refuse the result. Every other fork is refused
/// too, since the containers here are fulu's.
pub(super) fn require_fulu_slot(
    config: &Config,
    slot: Slot,
    message: &'static str,
) -> Result<(), ApiError> {
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

#[allow(clippy::too_many_arguments)]
async fn get_block(
    Path(slot): Path<String>,
    Query(query): Query<ProduceQuery>,
    State(store): State<Store>,
    Extension(engine): Extension<Option<EngineClient>>,
    Extension(sync_pool): Extension<SharedSyncCommitteePool>,
    Extension(fee_recipients): Extension<FeeRecipients>,
    Extension(OwnVersion(own_version)): Extension<OwnVersion>,
    builder: Option<Extension<Arc<Builder>>>,
    headers: HeaderMap,
) -> Response {
    let Ok(slot) = slot.parse::<Slot>() else {
        return ApiError::BadRequest("invalid slot").into_response();
    };
    // Ahead of the engine check, like the slot check below: a bad flag is the
    // caller's mistake, a 400 on any node.
    let randao = match randao_verification(
        query.skip_randao_verification.as_deref(),
        &query.randao_reveal,
    ) {
        Ok(randao) => randao,
        Err(err) => return err.into_response(),
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
        &sync_pool,
        &fee_recipients,
        &own_version,
        builder.as_ref().map(|Extension(builder)| builder.as_ref()),
        query.builder_boost_factor.unwrap_or(DEFAULT_BOOST_FACTOR),
        slot,
        query.randao_reveal,
        BlockProcessingOptions { randao },
        graffiti,
    )
    .await;
    let (produced, payload_value, fork) = match produced {
        Ok(produced) => produced,
        Err(err) => return err.into_response(),
    };

    let blinded = matches!(produced, Produced::Blinded(_));
    let accept = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok());
    let mut response = match (Encoding::from_accept(accept), produced) {
        (Encoding::Ssz, Produced::Full(contents)) => ssz_response(contents.to_ssz()),
        (Encoding::Ssz, Produced::Blinded(block)) => ssz_response(block.to_ssz()),
        (Encoding::Json, Produced::Full(contents)) => crate::json_response(serde_json::json!({
            "version": fork.as_str(),
            "execution_payload_blinded": false,
            "execution_payload_value": payload_value,
            "consensus_block_value": "0",
            "data": contents,
        })),
        (Encoding::Json, Produced::Blinded(block)) => crate::json_response(serde_json::json!({
            "version": fork.as_str(),
            "execution_payload_blinded": true,
            "execution_payload_value": payload_value,
            "consensus_block_value": "0",
            "data": block,
        })),
    };
    let headers = response.headers_mut();
    headers.insert(
        "eth-execution-payload-blinded",
        HeaderValue::from_static(if blinded { "true" } else { "false" }),
    );
    if let Ok(value) = HeaderValue::from_str(&payload_value) {
        headers.insert("eth-execution-payload-value", value);
    }
    // Not computed: the builder comparison here weighs the execution
    // payloads' values alone, and nothing else on this node reads it.
    headers.insert("eth-consensus-block-value", HeaderValue::from_static("0"));
    with_consensus_version(response, fork)
}

/// What `produceBlockV3` answers with.
enum Produced {
    /// The local block, with its blobs and cell proofs.
    Full(FuluBlockContents),
    /// The blinded block around a builder's bid.
    Blinded(BlindedBeaconBlock),
}

/// The block's consensus contents, packed once against the proposal state
/// and offered to both payloads.
struct Packed {
    attestations: Vec<Attestation>,
    operations: Operations,
    sync_aggregate: SyncAggregate,
}

impl Packed {
    /// Whether dropping the packed contents might save a block that failed to
    /// build.
    fn droppable(&self) -> bool {
        !self.attestations.is_empty()
            || !self.operations.is_empty()
            || self.sync_aggregate != empty_sync_aggregate()
    }
}

/// The local payload, checked and converted for a block but not yet built
/// into one, so choosing between it and a bid costs no state transition.
struct LocalParts {
    built: BuiltPayload,
    blobs: Blobs,
    kzg_proofs: CellKzgProofs,
    execution_requests: ExecutionRequests,
}

/// The blinded block around a validated bid, and what the bid pays.
struct BlindedCandidate {
    block: BlindedBeaconBlock,
    value: Uint256,
}

/// What to ask the builder for this slot.
struct BuilderRequest<'a> {
    builder: &'a Builder,
    pubkey: BlsPubkey,
    registration: ValidatorRegistrationV1,
    parent_hash: ExecutionBlockHash,
}

/// The block for `slot`, its payload's value in wei as a decimal string, and
/// the block's fork.
///
/// With a builder layered, the proposer registered through this node and the
/// circuit breaker quiet, the builder's bid is fetched alongside the local
/// payload. Both are checked without a state transition, [`choice::choose`]
/// picks one, and only that one is built into a block; the other is built only
/// if the first fails. Without a builder the block is built exactly as it is
/// without one.
#[allow(clippy::too_many_arguments)]
async fn produce(
    store: &Store,
    engine: &EngineClient,
    sync_pool: &SharedSyncCommitteePool,
    fee_recipients: &FeeRecipients,
    own_version: &ClientVersionV1,
    builder: Option<&Builder>,
    boost_factor: u64,
    slot: Slot,
    randao_reveal: BlsSignature,
    options: BlockProcessingOptions,
    graffiti: Bytes32,
) -> Result<(Produced, String, ForkName), ApiError> {
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
    let request =
        builder.and_then(|builder| builder_request(store, builder, &state, head_root, proposer));

    // Asked alongside the build rather than before it, so a healthy execution
    // client costs the block nothing for its version and a silent one costs it
    // at most the version's own timeout. The builder's bid is asked alongside
    // as well, bounded by its own header timeout.
    let (built, el_version, bid) = tokio::join!(
        build_payload(store, engine, fee_recipients, &state, head_root, proposer),
        graffiti::execution_client_version(engine, own_version),
        fetch_bid(request.as_ref(), slot),
    );
    let graffiti = graffiti::with_client_versions(graffiti, el_version.as_ref(), own_version);
    let packed = pack(store, sync_pool, &state, head_root, slot, &config);
    let local = built.and_then(|built| local_parts(built, slot));
    let mut bid = request
        .as_ref()
        .zip(bid)
        .and_then(|(request, bid)| accepted_bid(&state, &config, request, bid));

    let local_offer = local.as_ref().ok().map(|parts| LocalOffer {
        value: wei_u128(&parts.built.block_value),
        should_override_builder: parts.built.should_override_builder,
    });
    let bid_value = bid.as_ref().map(|bid| wei_u128(&bid.value));
    let order = if choice::choose(local_offer, bid_value, boost_factor) == Some(Source::Builder) {
        [Source::Builder, Source::Local]
    } else {
        [Source::Local, Source::Builder]
    };

    let (mut local, mut local_error) = match local {
        Ok(parts) => (Some(parts), None),
        Err(err) => (None, Some(err)),
    };
    for source in order {
        match source {
            Source::Builder => {
                let Some(message) = bid.take() else {
                    continue;
                };
                let blinded = blinded_block(
                    &state,
                    &config,
                    message,
                    &packed,
                    randao_reveal,
                    graffiti,
                    options,
                );
                if let Some(blinded) = blinded {
                    inc_payload_source(Source::Builder.label());
                    let value = decimal(&blinded.value);
                    info!(%slot, proposer, %value, "Produced a blinded block around the builder's bid");
                    return Ok((Produced::Blinded(blinded.block), value, fork));
                }
            }
            Source::Local => {
                let Some(parts) = local.take() else {
                    continue;
                };
                let assembled = local_block(
                    &state,
                    parts,
                    &packed,
                    randao_reveal,
                    graffiti,
                    &config,
                    options,
                    slot,
                );
                match assembled {
                    Ok((contents, value)) => {
                        if builder.is_some() {
                            inc_payload_source(Source::Local.label());
                        }
                        let block = &contents.block;
                        info!(
                            %slot,
                            proposer,
                            attestations = block.body.attestations.len(),
                            slashings = block.body.proposer_slashings.len()
                                + block.body.attester_slashings.len(),
                            exits = block.body.voluntary_exits.len(),
                            bls_changes = block.body.bls_to_execution_changes.len(),
                            transactions = block.body.execution_payload.transactions.len(),
                            blobs = block.body.blob_kzg_commitments.len(),
                            graffiti = %graffiti::display(&block.body.graffiti),
                            "Produced block"
                        );
                        return Ok((Produced::Full(contents), decimal(&value), fork));
                    }
                    Err(err) => local_error = Some(err),
                }
            }
        }
    }
    // The local error surfaces only when the builder did not step in.
    Err(local_error.unwrap_or(ApiError::Internal("the block failed to build")))
}

/// The block's consensus contents for `state`: attestations, operations and
/// the sync aggregate, each checked against `state`.
fn pack(
    store: &Store,
    sync_pool: &SharedSyncCommitteePool,
    state: &BeaconState,
    head_root: H256,
    slot: Slot,
    config: &Config,
) -> Packed {
    let candidates = store.attestation_pool().block_candidates();
    let attestations = pack_attestations(state, candidates);
    let operation_candidates = {
        let pool = store.operation_pool();
        Operations {
            proposer_slashings: pool.proposer_slashings(),
            attester_slashings: pool.attester_slashings(),
            voluntary_exits: pool.voluntary_exits(),
            bls_to_execution_changes: pool.bls_to_execution_changes(),
        }
    };
    let operations = pack_operations(state, operation_candidates, config);
    // What the committee signed at the previous slot over this block's parent,
    // verified exactly as `process_sync_aggregate` will check it against the
    // state the block is built on; a candidate that fails becomes the empty
    // aggregate rather than a block the chain would refuse.
    let candidate = sync_pool
        .lock()
        .expect("sync committee pool lock poisoned")
        .sync_aggregate(slot - 1, head_root);
    let sync_aggregate = candidate.map_or_else(empty_sync_aggregate, |candidate| {
        verified_sync_aggregate(state, candidate)
    });
    Packed {
        attestations,
        operations,
        sync_aggregate,
    }
}

/// The execution client's payload checked and converted for a block: its
/// blobs bundle against the commitments, the blobs and cell proofs into their
/// containers, and its execution requests parsed. No state transition runs.
fn local_parts(mut built: BuiltPayload, slot: Slot) -> Result<LocalParts, ApiError> {
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
    Ok(LocalParts {
        built,
        blobs,
        kzg_proofs,
        execution_requests,
    })
}

/// The local block: the execution client's payload around `packed`, with
/// its blobs and cell proofs, and the payload's value.
#[allow(clippy::too_many_arguments)]
fn local_block(
    state: &BeaconState,
    parts: LocalParts,
    packed: &Packed,
    randao_reveal: BlsSignature,
    graffiti: Bytes32,
    config: &Config,
    options: BlockProcessingOptions,
    slot: Slot,
) -> Result<(FuluBlockContents, Uint256), ApiError> {
    let LocalParts {
        built,
        blobs,
        kzg_proofs,
        execution_requests,
    } = parts;
    let inputs = |attestations, operations, sync_aggregate| BlockInputs {
        sync_aggregate,
        randao_reveal,
        graffiti,
        attestations,
        operations,
        execution_payload: built.execution_payload.clone(),
        blob_kzg_commitments: built.blobs_bundle.commitments.clone(),
        execution_requests: execution_requests.clone(),
    };
    let block = match assemble_block(
        state,
        inputs(
            packed.attestations.clone(),
            packed.operations.clone(),
            packed.sync_aggregate.clone(),
        ),
        config,
        options,
    ) {
        Ok(block) => block,
        // `pack_attestations` and `pack_operations` check every candidate
        // against this state, and the sync aggregate is verified against it
        // too, so this should not happen; but a block without them still earns
        // the proposal, and one that fails to build earns nothing.
        Err(err) if packed.droppable() => {
            warn!(%slot, %err, "Block with attestations, operations or a sync aggregate failed to build; retrying without");
            assemble_block(
                state,
                inputs(Vec::new(), Operations::default(), empty_sync_aggregate()),
                config,
                options,
            )
            .map_err(|_| ApiError::Internal("the block failed to build"))?
        }
        Err(_) => return Err(ApiError::Internal("the block failed to build")),
    };
    let contents = FuluBlockContents {
        block,
        kzg_proofs,
        blobs,
    };
    Ok((contents, built.block_value))
}

/// What to ask the builder for, if anything.
///
/// The builder is asked only when the proposer registered through this node
/// and the circuit breaker is quiet. A validator client that does not use
/// builders sends no registrations, so its validators never get here.
/// `get_block` has already refused every fork but fulu.
fn builder_request<'a>(
    store: &Store,
    builder: &'a Builder,
    state: &BeaconState,
    head_root: H256,
    proposer: ValidatorIndex,
) -> Option<BuilderRequest<'a>> {
    let BeaconState::Fulu(fulu) = state else {
        return None;
    };
    let pubkey = state.validator(proposer).ok()?.pubkey;
    let registration = builder
        .registrations
        .get(&pubkey, compute_epoch_at_slot(state.slot()))?;
    let optimistic = block_is_optimistic(store, head_root);
    let syncing = builder.sync_status.get() == SyncStatus::Syncing;
    if let Err(trip) = breaker::check(state, &builder.fallback, optimistic, syncing) {
        inc_builder_fallback(trip.label());
        info!(
            slot = state.slot(),
            reason = trip.label(),
            "The circuit breaker keeps the builder out; building locally"
        );
        return None;
    }
    Some(BuilderRequest {
        builder,
        pubkey,
        registration,
        parent_hash: fulu.latest_execution_payload_header.block_hash,
    })
}

/// The builder's bid, or `None` when it was not asked, had none, or failed.
async fn fetch_bid(request: Option<&BuilderRequest<'_>>, slot: Slot) -> Option<VersionedBid> {
    let request = request?;
    request
        .builder
        .client
        .get_header(slot, request.parent_hash, &request.pubkey)
        .await
        .inspect_err(|err| warn!(%slot, %err, "The builder gave no bid; building locally"))
        .ok()
        .flatten()
}

/// `bid`'s message, if the bid is acceptable. No state transition runs.
fn accepted_bid(
    state: &BeaconState,
    config: &Config,
    request: &BuilderRequest,
    bid: VersionedBid,
) -> Option<BuilderBid> {
    let slot = state.slot();
    let BeaconState::Fulu(fulu) = state else {
        return None;
    };
    let inputs = payload_inputs(state, config).ok()?;
    let context = BidContext {
        genesis_fork_version: config.genesis_fork_version,
        inputs: &inputs,
        parent_block_number: fulu.latest_execution_payload_header.block_number,
        parent_gas_limit: fulu.latest_execution_payload_header.gas_limit,
        target_gas_limit: request.registration.gas_limit,
        max_blobs: config.max_blobs_per_block(compute_epoch_at_slot(slot)),
    };
    if let Err(rejection) = bid::validate(&bid.bid, &context) {
        inc_bid_rejection(rejection.label());
        warn!(%slot, reason = rejection.label(), "Refusing the builder's bid");
        return None;
    }
    let message = bid.bid.message;
    if message.header.fee_recipient != request.registration.fee_recipient {
        // Expected: relays pay the proposer with a transaction in the payload
        // and name the builder as its fee recipient (docs/spec_deviations.md).
        debug!(%slot, "The bid's fee recipient is not the registered one");
    }
    Some(message)
}

/// The blinded block around an accepted bid, if it passes the state
/// transition.
#[allow(clippy::too_many_arguments)]
fn blinded_block(
    state: &BeaconState,
    config: &Config,
    message: BuilderBid,
    packed: &Packed,
    randao_reveal: BlsSignature,
    graffiti: Bytes32,
    options: BlockProcessingOptions,
) -> Option<BlindedCandidate> {
    let slot = state.slot();
    let assemble = |attestations, operations, sync_aggregate| {
        assemble_blinded_block(
            state,
            BlindedBlockInputs {
                randao_reveal,
                graffiti,
                attestations,
                operations,
                execution_payload_header: message.header.clone(),
                blob_kzg_commitments: message.blob_kzg_commitments.to_vec(),
                execution_requests: message.execution_requests.clone(),
                sync_aggregate,
            },
            config,
            options,
        )
    };
    let assembled = match assemble(
        packed.attestations.clone(),
        packed.operations.clone(),
        packed.sync_aggregate.clone(),
    ) {
        Err(err) if packed.droppable() => {
            warn!(%slot, %err, "Blinded block with attestations, operations or a sync aggregate failed to build; retrying without");
            assemble(Vec::new(), Operations::default(), empty_sync_aggregate())
        }
        other => other,
    };
    match assembled {
        Ok(block) => Some(BlindedCandidate {
            block,
            value: message.value,
        }),
        Err(err) => {
            inc_bid_rejection("state_transition");
            warn!(%slot, %err, "The builder's bid fails the state transition");
            None
        }
    }
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

    /// A fulu head with its proposer lookahead and sync committee filled in,
    /// which a block built on it needs, under a schedule that puts every slot
    /// at fulu.
    fn fulu_store() -> (Store, Slot) {
        use ethlambda_state_transition::beacon::helpers::{
            altair::get_next_sync_committee, fulu::initialize_proposer_lookahead,
        };
        let mut state = with_signing_validators_at(ForkName::Fulu, 64);
        let lookahead = initialize_proposer_lookahead(&state).unwrap();
        let sync_committee = get_next_sync_committee(&state).unwrap();
        let BeaconState::Fulu(inner) = &mut state else {
            unreachable!("built as fulu")
        };
        inner.proposer_lookahead = lookahead.try_into().unwrap();
        inner.current_sync_committee = sync_committee.clone();
        inner.next_sync_committee = sync_committee;
        let head_slot = state.slot();
        let (store, _root) =
            beacon_store_with_config(state, Config::mainnet().with_fork_epoch(ForkName::Fulu, 0));
        (store, head_slot)
    }

    fn produce_app(store: Store, engine: Option<EngineClient>) -> Router {
        routes()
            .with_state(store)
            .layer(Extension(engine))
            .layer(Extension(SharedSyncCommitteePool::default()))
            .layer(Extension(FeeRecipients::default()))
            .layer(Extension(OwnVersion(Arc::new(
                ethlambda_engine::types::ClientVersionV1 {
                    code: "LA".to_string(),
                    name: "ethlambda".to_string(),
                    version: "ethlambda/test".to_string(),
                    commit: "0x3c4d7e8f".to_string(),
                },
            ))))
    }

    fn infinity_reveal() -> String {
        hex::encode(bls::G2_POINT_AT_INFINITY)
    }

    fn produce_uri(slot: Slot, reveal: &str, flag: &str) -> String {
        format!("/eth/v3/validator/blocks/{slot}?randao_reveal=0x{reveal}{flag}")
    }

    #[tokio::test]
    async fn the_infinity_reveal_is_produced_only_when_the_flag_skips_its_verification() {
        let (store, head_slot) = fulu_store();
        let slot = head_slot + 1;
        let engine = super::super::validator_client_tests::fake_execution_client(0).await;

        for flag in ["&skip_randao_verification=", "&skip_randao_verification"] {
            let app = produce_app(store.clone(), Some(engine.clone()));
            let uri = produce_uri(slot, &infinity_reveal(), flag);
            let (status, json) = respond(app, Request::get(uri).body(Body::empty()).unwrap()).await;
            assert_eq!(status, StatusCode::OK, "{flag}: {json}");
            assert_eq!(
                json["data"]["block"]["body"]["randao_reveal"],
                format!("0x{}", infinity_reveal()),
                "{flag}"
            );
        }

        // Without the flag the reveal is verified, and the infinity one fails.
        let app = produce_app(store, Some(engine));
        let uri = produce_uri(slot, &infinity_reveal(), "");
        let (status, _) = respond(app, Request::get(uri).body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn the_randao_skip_flag_is_refused_with_a_value_or_a_real_reveal() {
        let (store, head_slot) = fulu_store();
        let slot = head_slot + 1;
        let get = |uri: String| Request::get(uri).body(Body::empty()).unwrap();

        let (status, json) = respond(
            produce_app(store.clone(), None),
            get(produce_uri(
                slot,
                &"00".repeat(96),
                "&skip_randao_verification",
            )),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            json["message"],
            "randao_reveal must be the point at infinity when skip_randao_verification is set"
        );

        let (status, json) = respond(
            produce_app(store, None),
            get(produce_uri(
                slot,
                &infinity_reveal(),
                "&skip_randao_verification=true",
            )),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            json["message"],
            "skip_randao_verification does not take a value"
        );
    }

    #[tokio::test]
    async fn producing_a_gloas_slot_is_a_400_even_with_no_execution_client() {
        let (store, head_slot) = gloas_scheduled_store();
        let app = routes()
            .with_state(store)
            .layer(Extension(None::<EngineClient>))
            .layer(Extension(SharedSyncCommitteePool::default()))
            .layer(Extension(FeeRecipients::default()))
            .layer(Extension(OwnVersion(Arc::new(
                ethlambda_engine::types::ClientVersionV1 {
                    code: "LA".to_string(),
                    name: "ethlambda".to_string(),
                    version: "ethlambda/test".to_string(),
                    commit: "0x3c4d7e8f".to_string(),
                },
            ))));
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

    /// A fulu body in either encoding reaches the same check and gets the same
    /// answer, here the refusal of a slot the schedule does not place at fulu.
    #[tokio::test]
    async fn fulu_block_contents_are_accepted_as_json_exactly_as_ssz() {
        let (store, _) = gloas_scheduled_store();
        let contents = FuluSignedBlockContents {
            signed_block: containers::electra::SignedBeaconBlock {
                message: containers::electra::BeaconBlock {
                    slot: 64,
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
        let back: FuluSignedBlockContents =
            serde_json::from_slice(&serde_json::to_vec(&contents).unwrap()).unwrap();
        assert_eq!(back, contents);

        let mut answers = Vec::new();
        for (content_type, body) in [
            (crate::SSZ_CONTENT_TYPE, contents.to_ssz()),
            ("application/json", serde_json::to_vec(&contents).unwrap()),
        ] {
            let network: RpcToP2PRef = Arc::new(RecordingNetwork::default());
            let app = routes().with_state(store.clone()).layer(Extension(network));
            let request = Request::post("/eth/v2/beacon/blocks")
                .header("eth-consensus-version", "fulu")
                .header(header::CONTENT_TYPE, content_type)
                .body(Body::from(body))
                .unwrap();
            answers.push(respond(app, request).await);
        }
        assert_eq!(answers[0].0, StatusCode::BAD_REQUEST);
        assert_eq!(answers[0], answers[1]);
    }

    #[tokio::test]
    async fn a_block_content_type_other_than_json_or_ssz_is_a_415() {
        let (store, _) = gloas_scheduled_store();
        let network: RpcToP2PRef = Arc::new(RecordingNetwork::default());
        let app = routes().with_state(store).layer(Extension(network));
        let request = Request::post("/eth/v2/beacon/blocks")
            .header("eth-consensus-version", "fulu")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("{}"))
            .unwrap();
        let (status, _) = respond(app, request).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
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

        // The same block as JSON is accepted and published identically, and a
        // forged one refused.
        let post_json = |network: Arc<RecordingNetwork>,
                         signed: &containers::gloas::SignedBeaconBlock| {
            let network: RpcToP2PRef = network;
            let app = routes().with_state(store.clone()).layer(Extension(network));
            let request = Request::post("/eth/v2/beacon/blocks")
                .header("eth-consensus-version", "gloas")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(signed).unwrap()))
                .unwrap();
            respond(app, request)
        };
        let via_json = Arc::new(RecordingNetwork::default());
        let (status, _) = post_json(via_json.clone(), &signed).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            *via_json.blocks.lock().unwrap(),
            *network.blocks.lock().unwrap()
        );

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

    use crate::beacon::builder_client::mock_relay::MockRelay;
    use crate::beacon::builder_client::{BuilderClient, VersionedBid};
    use crate::beacon::builder_flow::breaker::FallbackThresholds;
    use ethlambda_blockchain::SyncStatusController;
    use ethlambda_types::beacon::builder::{BuilderBid, ValidatorRegistrationV1};
    use ethlambda_types::beacon::containers::capella;
    use ethlambda_types::beacon::containers::deneb::{ExecutionPayloadHeader, KzgCommitments};
    use ethlambda_types::beacon::containers::electra::{self, ExecutionRequests};
    use libssz::SszDecode as _;
    use std::time::Duration;

    const ETH: u64 = 1_000_000_000_000_000_000;
    /// The registered gas limit the test proposer asks for.
    const TARGET_GAS_LIMIT: u64 = 60_000_000;

    /// Thresholds that never trip, so a test state's history does not decide
    /// whether the builder is asked.
    const NEVER_TRIP: FallbackThresholds = FallbackThresholds {
        skips: u64::MAX,
        skips_per_epoch: u64::MAX,
        epochs_since_finalization: u64::MAX,
    };

    /// A builder world for the next slot on `fulu_store()`: a mock relay, a
    /// `Builder` pointing at it with the proposer registered, and the
    /// advanced proposal state.
    struct BuilderWorld {
        store: Store,
        slot: Slot,
        state: BeaconState,
        relay: MockRelay,
        builder: Arc<Builder>,
    }

    async fn builder_world(registered: bool, sync: SyncStatus) -> BuilderWorld {
        let (store, head_slot) = fulu_store();
        let slot = head_slot + 1;
        let config = store.config();
        let (_, head_state) = super::super::validator::head(&store).unwrap();
        let state = advance_to_slot(&head_state, slot, &config).unwrap();
        let proposer = get_beacon_proposer_index(&state).unwrap();
        let pubkey = state.validator(proposer).unwrap().pubkey;
        let relay = MockRelay::start(config.genesis_fork_version).await;
        let client =
            BuilderClient::new(relay.url.clone(), Duration::from_secs(1), "ethlambda/test")
                .unwrap();
        let builder = Arc::new(Builder::new(
            client,
            NEVER_TRIP,
            SyncStatusController::new(sync),
        ));
        if registered {
            let registration = ValidatorRegistrationV1 {
                fee_recipient: ExecutionAddress::repeat_byte(0x11),
                gas_limit: TARGET_GAS_LIMIT,
                timestamp: 1,
                pubkey,
            };
            builder
                .registrations
                .record([&registration], compute_epoch_at_slot(slot));
        }
        BuilderWorld {
            store,
            slot,
            state,
            relay,
            builder,
        }
    }

    impl BuilderWorld {
        /// A bid of `value` wei that passes every check for this slot, with
        /// `edit` applied before the relay signs it.
        fn offer(&self, value: u64, edit: impl FnOnce(&mut BuilderBid)) {
            let config = self.store.config();
            let inputs = payload_inputs(&self.state, &config).unwrap();
            let BeaconState::Fulu(fulu) = &self.state else {
                unreachable!("built as fulu")
            };
            let parent_gas_limit = fulu.latest_execution_payload_header.gas_limit;
            let step = (parent_gas_limit / 1024).saturating_sub(1);
            let withdrawals: capella::Withdrawals = inputs.withdrawals.clone().try_into().unwrap();
            let mut header =
                ExecutionPayloadHeader::from(&electra::BeaconBlockBody::empty().execution_payload);
            header.parent_hash = inputs.parent_hash;
            header.prev_randao = inputs.prev_randao;
            header.timestamp = inputs.timestamp;
            header.block_number = fulu.latest_execution_payload_header.block_number + 1;
            header.withdrawals_root = withdrawals.hash_tree_root();
            header.gas_limit = TARGET_GAS_LIMIT.clamp(
                parent_gas_limit - step,
                parent_gas_limit.saturating_add(step),
            );
            header.block_hash = ExecutionBlockHash::repeat_byte(0xbb);
            let mut message = BuilderBid {
                header,
                blob_kzg_commitments: KzgCommitments::default(),
                execution_requests: ExecutionRequests::default(),
                value: Uint256::from(value),
                pubkey: self.relay.pubkey(),
            };
            edit(&mut message);
            let bid = self.relay.sign_bid(message);
            self.relay.offer(VersionedBid {
                fork: ForkName::Fulu,
                bid,
            });
        }

        fn app(&self, engine: Option<EngineClient>) -> Router {
            produce_app(self.store.clone(), engine).layer(Extension(self.builder.clone()))
        }

        fn uri(&self, query: &str) -> String {
            format!(
                "{}{query}",
                produce_uri(self.slot, &infinity_reveal(), "&skip_randao_verification")
            )
        }
    }

    /// What a `produceBlockV3` answer says about the payload it carries.
    struct Answer {
        status: StatusCode,
        blinded: Option<String>,
        value: Option<String>,
        json: serde_json::Value,
    }

    impl Answer {
        /// The answer was a 200 whose headers and body say `blinded` and
        /// `value` (wei, decimal), and the relay was asked `header_requests`
        /// times.
        fn assert(&self, world: &BuilderWorld, blinded: bool, value: &str, header_requests: usize) {
            assert_eq!(self.status, StatusCode::OK, "{}", self.json);
            assert_eq!(
                self.blinded.as_deref(),
                Some(if blinded { "true" } else { "false" }),
                "{}",
                self.json
            );
            assert_eq!(self.value.as_deref(), Some(value), "{}", self.json);
            assert_eq!(served_blinded(&self.json), blinded, "{}", self.json);
            assert_eq!(
                world.relay.header_requests().len(),
                header_requests,
                "{}",
                self.json
            );
        }
    }

    async fn produce_answer(
        world: &BuilderWorld,
        engine: Option<EngineClient>,
        accept: Option<&str>,
        query: &str,
    ) -> Answer {
        let mut request = Request::get(world.uri(query));
        if let Some(accept) = accept {
            request = request.header("accept", accept);
        }
        let response = world
            .app(engine)
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .map(|value| value.to_str().unwrap().to_owned())
        };
        let (status, blinded, value) = (
            response.status(),
            header("eth-execution-payload-blinded"),
            header("eth-execution-payload-value"),
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        Answer {
            status,
            blinded,
            value,
            json: serde_json::from_slice(&body).unwrap_or_default(),
        }
    }

    async fn produce(
        world: &BuilderWorld,
        engine_value: &'static str,
        override_builder: bool,
        query: &str,
    ) -> Answer {
        let engine = super::super::validator_client_tests::fake_execution_client_paying(
            engine_value,
            override_builder,
        )
        .await;
        produce_answer(world, Some(engine), None, query).await
    }

    fn served_blinded(json: &serde_json::Value) -> bool {
        json["execution_payload_blinded"] == serde_json::json!(true)
    }

    /// An execution client that is not there.
    fn dead_engine() -> EngineClient {
        EngineClient::new(
            "http://127.0.0.1:1".to_owned(),
            ethlambda_engine::JwtSecret::new([0x0f; 32]),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn a_bid_worth_more_than_the_local_payload_is_served_blinded() {
        let world = builder_world(true, SyncStatus::Synced).await;
        world.offer(ETH, |_| {});
        let answer = produce(&world, "0x2a", false, "").await;
        answer.assert(&world, true, &ETH.to_string(), 1);
        assert_eq!(
            answer.json["data"]["slot"],
            serde_json::json!(world.slot.to_string())
        );
        assert_eq!(
            answer.json["data"]["body"]["execution_payload_header"]["block_hash"],
            serde_json::json!(format!("0x{}", "bb".repeat(32)))
        );
    }

    #[tokio::test]
    async fn a_tie_keeps_the_local_payload() {
        let world = builder_world(true, SyncStatus::Synced).await;
        world.offer(ETH, |_| {});
        // 1 ETH in hex wei.
        let answer = produce(&world, "0xde0b6b3a7640000", false, "").await;
        answer.assert(&world, false, &ETH.to_string(), 1);
    }

    #[tokio::test]
    async fn a_boost_factor_of_zero_keeps_the_local_payload() {
        let world = builder_world(true, SyncStatus::Synced).await;
        world.offer(ETH, |_| {});
        let answer = produce(&world, "0x2a", false, "&builder_boost_factor=0").await;
        answer.assert(&world, false, "42", 1);
    }

    #[tokio::test]
    async fn the_maximum_boost_factor_takes_the_bid() {
        let world = builder_world(true, SyncStatus::Synced).await;
        world.offer(1_000_000_000, |_| {});
        let query = format!("&builder_boost_factor={}", u64::MAX);
        let answer = produce(&world, "0xde0b6b3a7640000", false, &query).await;
        answer.assert(&world, true, "1000000000", 1);
    }

    #[tokio::test]
    async fn the_execution_clients_override_keeps_the_local_payload() {
        let world = builder_world(true, SyncStatus::Synced).await;
        // 10 ETH: the largest round value a u64 of wei holds.
        world.offer(10 * ETH, |_| {});
        let answer = produce(&world, "0x2a", true, "").await;
        answer.assert(&world, false, "42", 1);
    }

    #[tokio::test]
    async fn an_unregistered_proposer_never_reaches_the_builder() {
        let world = builder_world(false, SyncStatus::Synced).await;
        world.offer(ETH, |_| {});
        let answer = produce(&world, "0x2a", false, "").await;
        answer.assert(&world, false, "42", 0);
    }

    #[tokio::test]
    async fn a_syncing_node_keeps_the_builder_out() {
        let world = builder_world(true, SyncStatus::Syncing).await;
        world.offer(ETH, |_| {});
        let answer = produce(&world, "0x2a", false, "").await;
        answer.assert(&world, false, "42", 0);
    }

    #[tokio::test]
    async fn a_bid_on_the_wrong_parent_is_dropped() {
        let world = builder_world(true, SyncStatus::Synced).await;
        world.offer(ETH, |bid| {
            bid.header.parent_hash = ExecutionBlockHash::repeat_byte(9)
        });
        let answer = produce(&world, "0x2a", false, "").await;
        answer.assert(&world, false, "42", 1);
    }

    #[tokio::test]
    async fn a_bid_on_the_wrong_block_number_is_dropped() {
        let world = builder_world(true, SyncStatus::Synced).await;
        world.offer(ETH, |bid| bid.header.block_number += 5);
        let answer = produce(&world, "0x2a", false, "").await;
        answer.assert(&world, false, "42", 1);
    }

    #[tokio::test]
    async fn without_a_local_payload_the_bid_is_served() {
        let world = builder_world(true, SyncStatus::Synced).await;
        world.offer(ETH, |_| {});
        let answer = produce_answer(&world, Some(dead_engine()), None, "").await;
        answer.assert(&world, true, &ETH.to_string(), 1);
    }

    #[tokio::test]
    async fn without_a_bid_or_a_local_payload_there_is_no_block() {
        let world = builder_world(true, SyncStatus::Synced).await;
        let answer = produce_answer(&world, Some(dead_engine()), None, "").await;
        assert_ne!(answer.status, StatusCode::OK, "{}", answer.json);
        assert_eq!(world.relay.header_requests().len(), 1);
    }

    #[tokio::test]
    async fn an_unreachable_builder_leaves_the_local_payload() {
        let mut world = builder_world(true, SyncStatus::Synced).await;
        // The same registered proposer, with a builder nothing listens at.
        let client = BuilderClient::new(
            "http://127.0.0.1:1".to_owned(),
            Duration::from_secs(1),
            "ethlambda/test",
        )
        .unwrap();
        let dead = Arc::new(Builder::new(
            client,
            NEVER_TRIP,
            SyncStatusController::new(SyncStatus::Synced),
        ));
        let proposer = get_beacon_proposer_index(&world.state).unwrap();
        let registration = ValidatorRegistrationV1 {
            fee_recipient: ExecutionAddress::repeat_byte(0x11),
            gas_limit: TARGET_GAS_LIMIT,
            timestamp: 1,
            pubkey: world.state.validator(proposer).unwrap().pubkey,
        };
        dead.registrations
            .record([&registration], compute_epoch_at_slot(world.slot));
        world.builder = dead;
        let answer = produce(&world, "0x2a", false, "").await;
        answer.assert(&world, false, "42", 0);
    }

    #[tokio::test]
    async fn a_blinded_block_is_served_in_ssz_with_its_headers() {
        let world = builder_world(true, SyncStatus::Synced).await;
        world.offer(ETH, |_| {});
        let engine =
            super::super::validator_client_tests::fake_execution_client_paying("0x2a", false).await;
        let request = Request::get(world.uri(""))
            .header("accept", "application/octet-stream")
            .body(Body::empty())
            .unwrap();
        let response = world.app(Some(engine)).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["eth-execution-payload-blinded"], "true");
        assert_eq!(
            response.headers()["eth-execution-payload-value"],
            ETH.to_string().as_str()
        );
        assert_eq!(world.relay.header_requests().len(), 1);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let block = BlindedBeaconBlock::from_ssz_bytes(&body).unwrap();
        assert_eq!(block.slot, world.slot);
    }

    use ethlambda_state_transition::beacon::helpers::accessors::get_domain;
    use ethlambda_state_transition::beacon::helpers::misc::compute_signing_root;
    use ethlambda_state_transition::beacon::helpers::test_state::sign_for;
    use ethlambda_types::beacon::builder::SignedBlindedBeaconBlock;
    use ethlambda_types::beacon::constants::DOMAIN_BEACON_PROPOSER;
    use ethlambda_types::beacon::primitives::Root;

    /// A blinded block for `world`'s slot on its head, signed by the slot's
    /// proposer (or by `signer`, to forge it), with `graffiti` to make
    /// distinct blocks.
    fn signed_blinded(
        world: &BuilderWorld,
        graffiti: u8,
        signer: Option<usize>,
    ) -> SignedBlindedBeaconBlock {
        let (head_root, _) = super::super::validator::head(&world.store).unwrap();
        let proposer = get_beacon_proposer_index(&world.state).unwrap();
        let mut body = electra::BeaconBlockBody::empty();
        body.graffiti = Bytes32::repeat_byte(graffiti);
        let block = electra::BeaconBlock {
            slot: world.slot,
            proposer_index: proposer,
            parent_root: head_root,
            state_root: Root::ZERO,
            body,
        };
        let message = BlindedBeaconBlock::from(block);
        let domain = get_domain(&world.state, DOMAIN_BEACON_PROPOSER, None);
        let root = compute_signing_root(message.hash_tree_root(), domain);
        let signature = sign_for(signer.unwrap_or(proposer as usize), root);
        SignedBlindedBeaconBlock { message, signature }
    }

    async fn post_blinded(
        app: Router,
        block: &SignedBlindedBeaconBlock,
    ) -> (StatusCode, serde_json::Value) {
        let request = Request::post("/eth/v2/beacon/blinded_blocks")
            .header("content-type", "application/octet-stream")
            .header("eth-consensus-version", "fulu")
            .body(Body::from(block.to_ssz()))
            .unwrap();
        respond(app, request).await
    }

    fn publish_app(world: &BuilderWorld) -> Router {
        let network: RpcToP2PRef = Arc::new(RecordingNetwork::default());
        routes()
            .with_state(world.store.clone())
            .layer(Extension(network))
            .layer(Extension(world.builder.clone()))
    }

    #[tokio::test]
    async fn a_signed_blinded_block_goes_to_the_builder() {
        let world = builder_world(true, SyncStatus::Synced).await;
        let block = signed_blinded(&world, 1, None);
        let (status, json) = post_blinded(publish_app(&world), &block).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(world.relay.blinded_blocks(), [block]);
    }

    #[tokio::test]
    async fn a_forged_blinded_block_never_reaches_the_builder() {
        let world = builder_world(true, SyncStatus::Synced).await;
        let proposer = get_beacon_proposer_index(&world.state).unwrap() as usize;
        let forged = signed_blinded(&world, 1, Some(proposer + 1));
        let (status, _) = post_blinded(publish_app(&world), &forged).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(world.relay.blinded_blocks().is_empty());
    }

    #[tokio::test]
    async fn a_second_different_block_for_the_slot_is_refused() {
        let world = builder_world(true, SyncStatus::Synced).await;
        let app = publish_app(&world);
        let first = signed_blinded(&world, 1, None);
        let second = signed_blinded(&world, 2, None);
        assert_eq!(post_blinded(app.clone(), &first).await.0, StatusCode::OK);
        assert_eq!(post_blinded(app.clone(), &first).await.0, StatusCode::OK);
        let (status, json) = post_blinded(app, &second).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");
        assert_eq!(world.relay.blinded_blocks(), [first.clone(), first]);
    }

    #[tokio::test]
    async fn the_builders_answer_decides_the_status() {
        for (answer, expected) in [
            (StatusCode::BAD_REQUEST, StatusCode::BAD_REQUEST),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            let world = builder_world(true, SyncStatus::Synced).await;
            world.relay.answer_submissions_with(answer);
            let block = signed_blinded(&world, 1, None);
            let (status, json) = post_blinded(publish_app(&world), &block).await;
            assert_eq!(status, expected, "{answer}: {json}");
        }
    }

    #[tokio::test]
    async fn without_a_builder_a_blinded_block_is_a_server_error() {
        let world = builder_world(true, SyncStatus::Synced).await;
        let network: RpcToP2PRef = Arc::new(RecordingNetwork::default());
        let app = routes()
            .with_state(world.store.clone())
            .layer(Extension(network));
        let block = signed_blinded(&world, 1, None);
        let (status, _) = post_blinded(app, &block).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn a_claim_survives_a_failed_submission() {
        let world = builder_world(true, SyncStatus::Synced).await;
        world
            .relay
            .answer_submissions_with(StatusCode::INTERNAL_SERVER_ERROR);
        let app = publish_app(&world);
        let first = signed_blinded(&world, 1, None);
        let second = signed_blinded(&world, 2, None);
        assert_eq!(
            post_blinded(app.clone(), &first).await.0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        // The slot stays claimed, so a different block is refused outright.
        assert_eq!(
            post_blinded(app.clone(), &second).await.0,
            StatusCode::BAD_REQUEST
        );
        // The same block is a retry, and goes to the builder again.
        assert_eq!(
            post_blinded(app, &first).await.0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(world.relay.blinded_blocks(), [first.clone(), first]);
    }

    #[tokio::test]
    async fn a_block_published_in_full_blocks_a_different_blinded_one() {
        let world = builder_world(true, SyncStatus::Synced).await;
        // A full block for the slot from the local path, signed by its proposer.
        let answer = produce(&world, "0x2a", false, "").await;
        answer.assert(&world, false, "42", 1);
        let mut contents: FuluBlockContents =
            serde_json::from_value(answer.json["data"].clone()).unwrap();
        // The test store keys its head by a root that is not its header's, so
        // the block names the stored key as its parent, as `signed_blinded` does.
        let (head_root, _) = super::super::validator::head(&world.store).unwrap();
        contents.block.parent_root = head_root;
        let proposer = get_beacon_proposer_index(&world.state).unwrap();
        let domain = get_domain(&world.state, DOMAIN_BEACON_PROPOSER, None);
        let signing_root = compute_signing_root(contents.block.hash_tree_root(), domain);
        let signed = FuluSignedBlockContents {
            signed_block: electra::SignedBeaconBlock {
                message: contents.block,
                signature: sign_for(proposer as usize, signing_root),
            },
            kzg_proofs: contents.kzg_proofs,
            blobs: contents.blobs,
        };

        let network = Arc::new(RecordingNetwork::default());
        let p2p: RpcToP2PRef = network.clone();
        let app = routes()
            .with_state(world.store.clone())
            .layer(Extension(p2p))
            .layer(Extension(world.builder.clone()));
        let request = Request::post("/eth/v2/beacon/blocks")
            .header("content-type", "application/octet-stream")
            .header("eth-consensus-version", "fulu")
            .body(Body::from(signed.to_ssz()))
            .unwrap();
        let (status, json) = respond(app.clone(), request).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(network.blocks.lock().unwrap().len(), 1);

        let blinded = signed_blinded(&world, 1, None);
        let (status, json) = post_blinded(app, &blinded).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");
        assert!(world.relay.blinded_blocks().is_empty());
    }

    #[tokio::test]
    async fn an_oversized_blinded_block_is_a_413() {
        let world = builder_world(true, SyncStatus::Synced).await;
        let request = Request::post("/eth/v2/beacon/blinded_blocks")
            .header("content-type", "application/octet-stream")
            .header("eth-consensus-version", "fulu")
            .body(Body::from(vec![
                0u8;
                super::super::MAX_PUBLISH_BODY_BYTES + 1
            ]))
            .unwrap();
        let (status, _) = respond(publish_app(&world), request).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }
}
