//! Gloas block production and payload envelope publication.
//!
//! `POST /eth/v4/validator/blocks/{slot}` (`produceBlockV4`) builds a
//! self-built block with this node's own execution client and hands the
//! validator client the block, and, with `include_payload`, the unsigned
//! envelope that reveals its payload plus the blobs and cell proofs. The three
//! pieces come back separately because a gloas proposer signs the block and
//! the envelope on their own: the block goes out first through
//! `POST /eth/v2/beacon/blocks` (see `proposal.rs`), the envelope after it
//! through `POST /eth/v1/beacon/execution_payload_envelopes`, which also
//! publishes the data columns of the blobs (a builder's duty in gloas, which a
//! self-building proposer therefore takes on).
//!
//! `GET /eth/v1/validator/execution_payload_envelopes/{slot}/{beacon_block_root}`
//! serves the envelope back for a validator client that asked for the block
//! with `include_payload=false`.
//!
//! The node always builds a local payload when it has an execution client, and
//! may instead build on a bid it saw over p2p (`bid_selection` decides, from the
//! request's `BuilderConfig`). A bid-won block comes back bare: the builder
//! reveals the payload, so nothing is cached here and this node never signs or
//! publishes an envelope for it. The `builders` entries of the config (bid
//! requests to a builder's URL) are decoded and not consulted.
//!
//! A self-built payload's fee recipient and gas target come from the signed
//! proposer preferences for the slot when this node holds them.
//!
//! What `produceBlockV4` builds is kept in a small cache, keyed by slot and
//! block root and holding the current and the previous slot only, so the
//! envelope and the blobs can be served and published without the caller
//! sending them back (`Eth-Blob-Data-Included: false`).

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Extension, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ethlambda_blockchain::checkpoint_hash;
use ethlambda_engine::{
    CustodyColumns, EngineClient, ForkchoiceStateV1,
    building::{BuiltGloasPayload, PayloadAttributesV3, PayloadAttributesV4, PayloadAttributesV5},
    types::ClientVersionV1,
};
use ethlambda_network_api::RpcToP2PRef;
use ethlambda_state_transition::beacon::{
    block_production::{advance_to_slot, empty_sync_aggregate, verified_sync_aggregate},
    bls,
    builder_market::SharedBuilderMarket,
    fork_choice::{
        get_head_node, gloas_verify_data_column_sidecar,
        gloas_verify_data_column_sidecar_kzg_proofs, should_build_on_full,
    },
    gloas_block_production::{
        GloasBidBlockInputs, GloasBlockInputs, GloasPayloadInputs, GloasProduced,
        assemble_gloas_block, assemble_gloas_block_on_bid, bid_is_includable,
        gloas_data_column_sidecars, gloas_payload_inputs, pack_gloas_attestations,
        pack_payload_attestations, parse_gloas_execution_requests,
    },
    gossip::proposer_preferences::dependent_root_at,
    helpers::{
        accessors::{get_beacon_proposer_index, get_domain},
        misc::compute_signing_root,
    },
    inclusion_list::{get_inclusion_list_committee, inclusion_list_dependent_root},
    payload_attestation_pool::SharedPayloadAttestationPool,
    stf::gloas::verify_execution_payload_envelope_signature,
    sync_committee_pool::SharedSyncCommitteePool,
};
use ethlambda_storage::Store;
use ethlambda_types::{
    beacon::{
        config::Config,
        constants,
        containers::{
            self, BeaconState, DataColumnSidecar,
            altair::SyncAggregate,
            deneb::Blob,
            gloas::{
                BeaconBlock, ExecutionPayloadEnvelope, ExecutionRequests,
                SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope,
                SignedProposerPreferences,
            },
            heze::InclusionListBits,
        },
        fork::ForkName,
        fork_choice::{ForkChoiceNode, PayloadStatus},
        primitives::{BlsSignature, Bytes32, ExecutionAddress, HashTreeRoot as _, KzgProof, Slot},
        signing::compute_epoch_at_slot,
    },
    primitives::H256,
};
use libssz::SszEncode as _;
use libssz_derive::{SszDecode, SszEncode};
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::beacon::{
    ApiError, BodyEncoding,
    bid_selection::{LocalCandidate, PayloadChoice, bid_total_gwei, choose_payload, wei_u128},
    builder_config::{BuilderConfig, decode_builder_config},
    graffiti::{self, OwnVersion},
    proposal::{Blobs, CellKzgProofs, decimal, require_gloas_slot},
    validator::{FeeRecipients, head},
};
use crate::shared::content::{Encoding, ssz_response, with_consensus_version};
// The node's custody set as the Beacon API's handles carry it, renamed so it
// cannot be confused with the engine's bitfield of the same name.
use crate::CustodyColumns as NodeCustodyColumns;

/// How long `publishExecutionPayloadEnvelope` waits for a block this node has
/// not imported yet.
///
/// A validator client publishes the envelope right after `publishBlockV2`
/// returns, and that returns once the block is handed to the network actor, not
/// once the chain actor has imported it, so the envelope routinely arrives
/// first.
const BLOCK_WAIT: Duration = Duration::from_secs(4);
const BLOCK_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// What `produceBlockV4` built for one block, kept for the envelope endpoints.
#[derive(Debug, Clone)]
struct CachedPayload {
    envelope: ExecutionPayloadEnvelope,
    blobs: Vec<Vec<u8>>,
    cell_proofs: Vec<KzgProof>,
}

/// The current and previous slots' productions, by `(slot, block root)`.
#[derive(Debug, Clone, Default)]
pub(crate) struct PayloadCache(Arc<Mutex<BTreeMap<(Slot, H256), CachedPayload>>>);

impl PayloadCache {
    fn insert(&self, slot: Slot, block_root: H256, payload: CachedPayload) {
        let mut entries = self.0.lock().expect("payload cache lock poisoned");
        entries.insert((slot, block_root), payload);
        let keep_from = slot.saturating_sub(1);
        entries.retain(|(held, _), _| *held >= keep_from);
    }

    fn get(&self, slot: Slot, block_root: H256) -> Option<CachedPayload> {
        self.0
            .lock()
            .expect("payload cache lock poisoned")
            .get(&(slot, block_root))
            .cloned()
    }
}

/// Gloas's `BlockContents`, the Beacon API's envelope for a self-built block
/// with its payload: not a consensus container, so it lives with the API.
#[derive(Debug, Clone, PartialEq, SszEncode, SszDecode, serde::Serialize, serde::Deserialize)]
pub(crate) struct GloasBlockContents {
    pub(crate) block: BeaconBlock,
    pub(crate) execution_payload_envelope: ExecutionPayloadEnvelope,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::seq")]
    pub(crate) kzg_proofs: CellKzgProofs,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::ssz_hex_seq")]
    pub(crate) blobs: Blobs,
}

/// Gloas's `SignedExecutionPayloadEnvelopeContents`, what the stateless form of
/// `publishExecutionPayloadEnvelope` receives.
#[derive(Debug, Clone, PartialEq, SszEncode, SszDecode, serde::Serialize, serde::Deserialize)]
pub(crate) struct GloasSignedEnvelopeContents {
    pub(crate) signed_execution_payload_envelope: SignedExecutionPayloadEnvelope,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::seq")]
    pub(crate) kzg_proofs: CellKzgProofs,
    #[serde(with = "ethlambda_types::beacon::serde_helpers::ssz_hex_seq")]
    pub(crate) blobs: Blobs,
}

pub(crate) fn routes() -> Router<Store> {
    Router::new()
        .route("/eth/v4/validator/blocks/{slot}", post(post_produce_block))
        .route(
            "/eth/v1/validator/execution_payload_envelopes/{slot}/{beacon_block_root}",
            get(get_envelope),
        )
        .route(
            "/eth/v1/beacon/execution_payload_envelopes",
            post(post_envelope).layer(DefaultBodyLimit::max(super::MAX_PUBLISH_BODY_BYTES)),
        )
        .layer(Extension(PayloadCache::default()))
}

fn consensus_version(headers: &HeaderMap) -> Option<ForkName> {
    headers
        .get("eth-consensus-version")
        .and_then(|value| value.to_str().ok())
        .and_then(ForkName::parse)
}

#[derive(Debug, Deserialize)]
struct ProduceQuery {
    randao_reveal: BlsSignature,
    #[serde(default)]
    graffiti: Option<H256>,
    include_payload: bool,
    /// Accepted for compatibility. Not honored: the block's state root comes
    /// from running it through the state transition, which verifies the reveal.
    #[serde(default)]
    #[allow(dead_code)]
    skip_randao_verification: Option<String>,
}

/// `POST /eth/v4/validator/blocks/{slot}`.
#[allow(clippy::too_many_arguments)]
async fn post_produce_block(
    Path(slot): Path<String>,
    query: Result<Query<ProduceQuery>, QueryRejection>,
    State(store): State<Store>,
    Extension(engine): Extension<Option<EngineClient>>,
    Extension(ptc_pool): Extension<SharedPayloadAttestationPool>,
    Extension(sync_pool): Extension<SharedSyncCommitteePool>,
    Extension(market): Extension<SharedBuilderMarket>,
    Extension(fee_recipients): Extension<FeeRecipients>,
    Extension(custody): Extension<NodeCustodyColumns>,
    Extension(cache): Extension<PayloadCache>,
    Extension(OwnVersion(own_version)): Extension<OwnVersion>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Ok(slot) = slot.parse::<Slot>() else {
        return ApiError::BadRequest("invalid slot").into_response();
    };
    let Ok(Query(query)) = query else {
        return ApiError::BadRequest(
            "randao_reveal and include_payload are required, graffiti is a 32-byte hex string",
        )
        .into_response();
    };
    if consensus_version(&headers).is_some_and(|fork| !fork.is_gloas_or_later()) {
        return ApiError::BadRequest("Eth-Consensus-Version must be gloas or heze").into_response();
    }
    // Ahead of the engine check: a slot this node cannot build is a 400 on any
    // node, not a 503 on one with no execution client.
    if let Err(err) = require_gloas_slot(
        &store.config(),
        slot,
        "this endpoint serves gloas slots only",
    ) {
        return err.into_response();
    }
    let builder_config = match decode_builder_config(&headers, &body) {
        Ok(config) => config,
        Err(err) => return err.into_response(),
    };
    let builders = builder_config.usable_entries(slot);
    if builders > 0 {
        debug!(%slot, builders, "Not consulting the builder entries of the block production request");
    }
    // Without an execution client a block can only be built on a bid, so a node
    // holding none for the slot has nothing to offer.
    if engine.is_none() && !market.has_bids_for_slot(slot) {
        return ApiError::ServiceUnavailable(
            "no execution client configured to build a payload with",
        )
        .into_response();
    }

    let graffiti = query.graffiti.unwrap_or(Bytes32::ZERO);
    let produced = produce(
        &store,
        engine.as_ref(),
        &market,
        &builder_config,
        &ptc_pool,
        &sync_pool,
        &fee_recipients,
        &custody,
        &own_version,
        slot,
        query.randao_reveal,
        graffiti,
    )
    .await;
    let produced = match produced {
        Ok(produced) => produced,
        Err(err) => return err.into_response(),
    };
    let accept = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok());
    let encoding = Encoding::from_accept(accept);
    let (mut response, included, payload_value) = match produced {
        Production::Bid { block, bid } => {
            let payload_value = bid_payload_value(&bid);
            let response = match encoding {
                Encoding::Ssz => ssz_response(block.to_ssz()),
                Encoding::Json => block_json(&payload_value, false, &block),
            };
            (response, false, payload_value)
        }
        Production::Local(Produced {
            built,
            block,
            envelope,
            payload_value,
        }) => {
            let block_root = block.hash_tree_root();
            cache.insert(
                slot,
                block_root,
                CachedPayload {
                    envelope: envelope.clone(),
                    blobs: built.blobs_bundle.blobs.clone(),
                    cell_proofs: built.blobs_bundle.proofs.clone(),
                },
            );
            let included = query.include_payload;
            let response = if included {
                let (Ok(kzg_proofs), Ok(blobs)) = (
                    CellKzgProofs::try_from(built.blobs_bundle.proofs),
                    blobs_list(built.blobs_bundle.blobs),
                ) else {
                    return ApiError::Internal("the blobs bundle exceeds the block's bounds")
                        .into_response();
                };
                let contents = GloasBlockContents {
                    block,
                    execution_payload_envelope: envelope,
                    kzg_proofs,
                    blobs,
                };
                match encoding {
                    Encoding::Ssz => ssz_response(contents.to_ssz()),
                    Encoding::Json => block_json(&payload_value, true, &contents),
                }
            } else {
                match encoding {
                    Encoding::Ssz => ssz_response(block.to_ssz()),
                    Encoding::Json => block_json(&payload_value, false, &block),
                }
            };
            (response, included, payload_value)
        }
    };
    let response_headers = response.headers_mut();
    response_headers.insert(
        "eth-execution-payload-included",
        HeaderValue::from_static(if included { "true" } else { "false" }),
    );
    if let Ok(value) = HeaderValue::from_str(&payload_value) {
        response_headers.insert("eth-execution-payload-value", value);
    }
    // Not computed: nothing here reads it, and the bid comparison compares
    // execution payload values only.
    response_headers.insert("eth-consensus-block-value", HeaderValue::from_static("0"));
    with_consensus_version(response, ForkName::Gloas)
}

/// A bid's total payment in Wei, the unit `Eth-Execution-Payload-Value` is in.
fn bid_payload_value(bid: &SignedExecutionPayloadBid) -> String {
    (u128::from(bid_total_gwei(&bid.message)) * 1_000_000_000).to_string()
}

fn block_json<T: serde::Serialize>(payload_value: &str, included: bool, data: &T) -> Response {
    crate::json_response(serde_json::json!({
        "version": ForkName::Gloas.as_str(),
        "consensus_block_value": "0",
        "execution_payload_value": payload_value,
        "execution_payload_included": included,
        "data": data,
    }))
}

fn blobs_list(blobs: Vec<Vec<u8>>) -> Result<Blobs, ()> {
    let blobs = blobs
        .into_iter()
        .map(|blob| Blob::try_from(blob).map_err(|_| ()))
        .collect::<Result<Vec<_>, ()>>()?;
    Blobs::try_from(blobs).map_err(|_| ())
}

/// What `produceBlockV4` built for one block.
// Short-lived (one per request), so boxing the larger variant buys nothing.
#[allow(clippy::large_enum_variant)]
enum Production {
    /// A block on this node's own payload, with the envelope that reveals it.
    Local(Produced),
    /// A block committing to a builder's bid. The builder reveals the payload,
    /// so there is no envelope and nothing to cache.
    Bid {
        block: BeaconBlock,
        bid: SignedExecutionPayloadBid,
    },
}

/// A self-built block.
struct Produced {
    built: BuiltGloasPayload,
    block: BeaconBlock,
    envelope: ExecutionPayloadEnvelope,
    payload_value: String,
}

/// This node's own payload for the slot, checked and ready to assemble.
struct LocalBuild {
    built: BuiltGloasPayload,
    execution_requests: ExecutionRequests,
}

/// What the build needs from the chain, read and advanced off the runtime.
struct Prepared {
    state: BeaconState,
    inputs: GloasPayloadInputs,
    proposer: u64,
    head_root: H256,
    head_slot: Slot,
    /// The parent envelope's requests when building on its full payload and
    /// the parent is gloas; empty otherwise.
    parent_requests: ExecutionRequests,
    /// The proposer's signed preferences for the slot, when this node holds
    /// them under the slot's dependent root.
    preferences: Option<SignedProposerPreferences>,
    /// Heze: the self-build bid's `inclusion_list_bits`. `None` at a gloas
    /// slot.
    inclusion_list_bits: Option<InclusionListBits>,
    /// Heze: the previous slot's inclusion list transactions, which the built
    /// payload must satisfy (`PayloadAttributesV5`). `None` at a gloas slot.
    inclusion_list_transactions: Option<Vec<Vec<u8>>>,
}

#[allow(clippy::too_many_arguments)]
async fn produce(
    store: &Store,
    engine: Option<&EngineClient>,
    market: &SharedBuilderMarket,
    builder_config: &BuilderConfig,
    ptc_pool: &SharedPayloadAttestationPool,
    sync_pool: &SharedSyncCommitteePool,
    fee_recipients: &FeeRecipients,
    custody: &NodeCustodyColumns,
    own_version: &ClientVersionV1,
    slot: Slot,
    randao_reveal: BlsSignature,
    graffiti: Bytes32,
) -> Result<Production, ApiError> {
    let prepare_store = store.clone();
    let prepare_market = market.clone();
    let prepared = tokio::task::spawn_blocking(move || {
        prepare(&prepare_store, &prepare_market, slot, randao_reveal)
    })
    .await
    .map_err(|_| ApiError::Internal("preparing the block failed"))??;

    // The local build first: bids keep arriving while the engine works, and
    // are read once it is done. The execution client's version is asked
    // alongside the build rather than before it, so a healthy execution client
    // costs the block nothing for its version and a silent one costs it at most
    // the version's own timeout.
    let (local, el_version) = tokio::join!(
        async {
            match engine {
                Some(engine) => {
                    Some(build_local(store, engine, fee_recipients, custody, &prepared, slot).await)
                }
                None => None,
            }
        },
        async {
            match engine {
                Some(engine) => graffiti::execution_client_version(engine, own_version).await,
                None => None,
            }
        },
    );
    let graffiti = graffiti::with_client_versions(graffiti, el_version.as_ref(), own_version);
    let (local, local_error) = match local {
        Some(Ok(local)) => (Some(local), None),
        Some(Err(err)) => (None, Some(err)),
        None => (None, None),
    };
    let bids = candidate_bids(market, &prepared);
    let candidate = local.as_ref().map(|local| LocalCandidate {
        value_wei: wei_u128(&local.built.block_value),
        should_override_builder: local.built.should_override_builder,
    });
    let choice = choose_payload(
        candidate.as_ref(),
        &bids,
        builder_config.min_bid,
        builder_config.builder_boost_factor,
    );

    let candidates = store.attestation_pool().block_candidates();
    let messages = ptc_pool
        .lock()
        .expect("payload attestation pool lock poisoned")
        .messages_for(slot.saturating_sub(1), prepared.head_root);
    // What the committee signed at the previous slot over this block's parent;
    // `assemble` verifies it against the block's own pre-state.
    let sync_candidate = sync_pool
        .lock()
        .expect("sync committee pool lock poisoned")
        .sync_aggregate(slot.saturating_sub(1), prepared.head_root);
    let config = store.config();
    let prepared = Arc::new(prepared);

    if let Some(PayloadChoice::Bid(bid)) = choice {
        let builder_index = bid.message.builder_index;
        let value_gwei = bid_total_gwei(&bid.message);
        let assembled = {
            let (config, prepared, bid) = (config.clone(), prepared.clone(), bid.clone());
            let (candidates, messages) = (candidates.clone(), messages.clone());
            let sync_candidate = sync_candidate.clone();
            tokio::task::spawn_blocking(move || {
                assemble_on_bid(
                    &config,
                    &prepared,
                    bid,
                    candidates,
                    messages,
                    sync_candidate,
                    randao_reveal,
                    graffiti,
                )
            })
            .await
        };
        match assembled {
            Ok(Ok(block)) => {
                info!(
                    %slot,
                    builder_index,
                    value_gwei,
                    "Produced gloas block on a builder bid"
                );
                return Ok(Production::Bid { block, bid });
            }
            Ok(Err(_)) | Err(_) if local.is_some() => {
                warn!(%slot, builder_index, "The winning bid failed to build; using the local payload");
            }
            Ok(Err(_)) | Err(_) => {
                return Err(ApiError::ServiceUnavailable(
                    "the winning bid failed to build",
                ));
            }
        }
    }

    let Some(local) = local else {
        return Err(local_error.unwrap_or(ApiError::ServiceUnavailable(
            "no execution client and no viable builder bid for the slot",
        )));
    };
    let LocalBuild {
        built,
        execution_requests,
    } = local;
    let payload_value = decimal(&built.block_value);
    let assembled = {
        let built = built.clone();
        tokio::task::spawn_blocking(move || {
            assemble(
                &config,
                &prepared,
                built,
                execution_requests,
                candidates,
                messages,
                sync_candidate,
                randao_reveal,
                graffiti,
            )
        })
        .await
        .map_err(|_| ApiError::Internal("assembling the block failed"))??
    };
    let GloasProduced { block, envelope } = assembled;
    info!(
        %slot,
        proposer = block.proposer_index,
        attestations = block.body.attestations.len(),
        payload_attestations = block.body.payload_attestations.len(),
        graffiti = %graffiti::display(&block.body.graffiti),
        blobs = built.blobs_bundle.blobs.len(),
        "Produced gloas block"
    );
    Ok(Production::Local(Produced {
        built,
        block,
        envelope,
        payload_value,
    }))
}

/// The pooled bids this node could build on at the prepared slot: on the same
/// parent payload the local build extends, with its `prev_randao`, packable
/// into a block on the advanced state, and, when the proposer's preferences are
/// held, paying the fee recipient they name. Value descending.
///
/// Bids on the head's parent (a proposer reorg) are not considered.
fn candidate_bids(
    market: &SharedBuilderMarket,
    prepared: &Prepared,
) -> Vec<SignedExecutionPayloadBid> {
    market
        .bids_for(
            prepared.state.slot(),
            prepared.head_root,
            prepared.inputs.head_block_hash,
        )
        .into_iter()
        .filter(|signed| {
            let bid = &signed.message;
            bid.prev_randao == prepared.inputs.prev_randao
                && prepared
                    .preferences
                    .as_ref()
                    .is_none_or(|prefs| prefs.message.fee_recipient == bid.fee_recipient)
                && bid_is_inclusive(prepared, bid)
                && bid_is_includable(&prepared.state, signed, &prepared.parent_requests)
        })
        .collect()
}

/// Heze: whether `bid`'s `inclusion_list_bits` cover every list in this node's
/// own view of the previous slot (`is_inclusion_list_bits_inclusive` with
/// `only_timely=False`, per heze `validator.md`), the bits the self-build would
/// claim. A gloas slot has no such rule.
fn bid_is_inclusive(prepared: &Prepared, bid: &containers::gloas::ExecutionPayloadBid) -> bool {
    let Some(local) = &prepared.inclusion_list_bits else {
        return true;
    };
    let Some(claimed) = &bid.inclusion_list_bits else {
        return false;
    };
    (0..local.len()).all(|i| !local.get(i).unwrap_or(false) || claimed.get(i).unwrap_or(false))
}

/// The chain-side half of production: pick the parent payload branch, advance
/// the head state to `slot` and derive the payload inputs from it.
fn prepare(
    store: &Store,
    market: &SharedBuilderMarket,
    slot: Slot,
    randao_reveal: BlsSignature,
) -> Result<Prepared, ApiError> {
    let config = store.config();
    let (head_root, head_state) = head(store)?;
    let head_slot = head_state.slot();
    if slot <= head_slot {
        return Err(ApiError::BadRequest("slot is not after the head block"));
    }

    // The payload branch of the head: the one fork choice recorded, or, when
    // it has not been recorded for this head yet, a fresh walk.
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
    debug_assert_ne!(payload_status, PayloadStatus::Pending);

    let head_is_gloas = matches!(
        store.get_signed_block(&head_root),
        Ok(Some(containers::SignedBeaconBlock::Gloas(_)))
    );
    let parent_requests = if build_on_full && head_is_gloas {
        store
            .get_execution_payload_envelope(&head_root)
            .map_err(|_| ApiError::Internal("store read failed"))?
            .ok_or(ApiError::ServiceUnavailable(
                "the parent's payload envelope is not held to build on",
            ))?
            .message
            .execution_requests
    } else {
        ExecutionRequests::default()
    };

    let state = advance_to_slot(&head_state, slot, &config)
        .map_err(|_| ApiError::Internal("advancing the head state failed"))?;
    let proposer = get_beacon_proposer_index(&state)
        .map_err(|_| ApiError::Internal("no proposer for the slot"))?;
    verify_randao_reveal(&state, proposer, randao_reveal)?;
    let mut inputs = gloas_payload_inputs(&state, build_on_full, &parent_requests, &config)
        .map_err(|_| ApiError::Internal("computing the payload attributes failed"))?;

    // The proposer's signed preferences for this slot, under the dependent root
    // the head's chain gives it. They name the fee recipient and gas target the
    // bids on the slot were judged against, so the self-build follows them too.
    let preferences = dependent_root_at(&head_state, head_root, slot)
        .and_then(|dependent_root| market.preferences(slot, dependent_root))
        .filter(|signed| signed.message.validator_index == proposer);
    if let Some(preferences) = &preferences {
        inputs.target_gas_limit = preferences.message.target_gas_limit;
    }
    let (inclusion_list_bits, inclusion_list_transactions) =
        match heze_inclusion_lists(store, &state, head_root, slot) {
            Some((bits, transactions)) => (Some(bits), Some(transactions)),
            None => (None, None),
        };
    Ok(Prepared {
        state,
        inputs,
        proposer,
        head_root,
        head_slot,
        parent_requests,
        preferences,
        inclusion_list_bits,
        inclusion_list_transactions,
    })
}

/// Heze's two inputs from the inclusion list store for a block at `slot`: the
/// self-build bid's `inclusion_list_bits` and the transactions the payload is
/// built to satisfy, both over every valid, non-equivocating list of the
/// previous slot this node holds (`only_timely=False`, the proposer's whole
/// view, per heze `validator.md`). `None` at a gloas slot.
///
/// Read once, here, so the bid claims exactly the lists whose transactions
/// the execution client was asked to include.
fn heze_inclusion_lists(
    store: &Store,
    state: &BeaconState,
    head_root: H256,
    slot: Slot,
) -> Option<(InclusionListBits, Vec<Vec<u8>>)> {
    if state.fork_name() != ForkName::Heze {
        return None;
    }
    let Some(inclusion_list_slot) = slot.checked_sub(1) else {
        return Some((InclusionListBits::new(), Vec::new()));
    };
    let dependent_root = inclusion_list_dependent_root(store, head_root, inclusion_list_slot);
    let committee =
        match get_inclusion_list_committee(state, inclusion_list_slot, &*store.committee_cache()) {
            Ok(committee) => committee,
            Err(err) => {
                warn!(%slot, %err, "No inclusion list committee for the previous slot");
                return Some((InclusionListBits::new(), Vec::new()));
            }
        };
    let lists = store.inclusion_list_store();
    let bits = lists.bits(&committee, inclusion_list_slot, dependent_root, false);
    let transactions: Vec<Vec<u8>> = lists
        .transactions(inclusion_list_slot, dependent_root, false)
        .into_iter()
        .map(|transaction| transaction.to_vec())
        .collect();
    info!(
        %slot,
        inclusion_lists = lists.count(inclusion_list_slot, dependent_root),
        inclusion_list_transactions = transactions.len(),
        "Building on the previous slot's inclusion lists"
    );
    Some((bits, transactions))
}

/// A reveal that does not verify would fail the block's own state transition
/// later with an opaque error; here it is the caller's mistake and says so.
fn verify_randao_reveal(
    state: &BeaconState,
    proposer: u64,
    randao_reveal: BlsSignature,
) -> Result<(), ApiError> {
    let epoch = compute_epoch_at_slot(state.slot());
    let domain = get_domain(state, constants::DOMAIN_RANDAO, Some(epoch));
    let signing_root = compute_signing_root(epoch.hash_tree_root(), domain);
    let pubkey = state
        .validator(proposer)
        .map_err(|_| ApiError::Internal("the proposer is not in the registry"))?
        .pubkey;
    if bls::verify(&pubkey, signing_root, &randao_reveal) {
        Ok(())
    } else {
        Err(ApiError::BadRequest("invalid randao_reveal"))
    }
}

/// Ask the execution client to build on the chosen parent payload for the
/// prepared slot, collect what it built and check it is consistent.
async fn build_local(
    store: &Store,
    engine: &EngineClient,
    fee_recipients: &FeeRecipients,
    custody: &NodeCustodyColumns,
    prepared: &Prepared,
    slot: Slot,
) -> Result<LocalBuild, ApiError> {
    let built = build_payload(store, engine, fee_recipients, custody, prepared).await?;
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
    let execution_requests = parse_gloas_execution_requests(&built.execution_requests)
        .map_err(|_| ApiError::Internal("the execution client's request list is malformed"))?;
    Ok(LocalBuild {
        built,
        execution_requests,
    })
}

/// Where a self-built payload's fee recipient comes from: the proposer's signed
/// preferences, else `prepare_beacon_proposer`'s, else the zero address.
fn fee_recipient_for(fee_recipients: &FeeRecipients, prepared: &Prepared) -> ExecutionAddress {
    if let Some(preferences) = &prepared.preferences {
        debug!(
            proposer = prepared.proposer,
            "Using the signed proposer preferences' fee recipient"
        );
        return preferences.message.fee_recipient;
    }
    let prepared_recipient = fee_recipients
        .lock()
        .expect("fee recipient lock poisoned")
        .get(&prepared.proposer)
        .copied();
    match prepared_recipient {
        Some(recipient) => {
            debug!(
                proposer = prepared.proposer,
                "Using the fee recipient from prepare_beacon_proposer"
            );
            recipient
        }
        None => {
            warn!(
                proposer = prepared.proposer,
                "No fee recipient for the proposer; using the zero address"
            );
            ExecutionAddress::ZERO
        }
    }
}

/// Ask the execution client to build on the chosen parent payload for the
/// prepared slot, then collect what it built.
///
/// Collected straight away rather than after waiting, as the fulu path does: the
/// execution client starts with a valid payload and improves it, so an early
/// `getPayload` always answers, and the validator client asks at the start of
/// the slot, when the block is due.
async fn build_payload(
    store: &Store,
    engine: &EngineClient,
    fee_recipients: &FeeRecipients,
    custody: &NodeCustodyColumns,
    prepared: &Prepared,
) -> Result<BuiltGloasPayload, ApiError> {
    let inputs = &prepared.inputs;
    let fee_recipient = fee_recipient_for(fee_recipients, prepared);
    let forkchoice = ForkchoiceStateV1 {
        head_block_hash: inputs.head_block_hash,
        safe_block_hash: checkpoint_hash(store, store.beacon_justified_checkpoint().root),
        finalized_block_hash: checkpoint_hash(store, store.beacon_finalized_checkpoint().root),
    };
    let attributes = PayloadAttributesV4 {
        v3: PayloadAttributesV3 {
            timestamp: inputs.timestamp,
            prev_randao: inputs.prev_randao,
            suggested_fee_recipient: fee_recipient,
            withdrawals: inputs.withdrawals.clone(),
            parent_beacon_block_root: inputs.parent_beacon_block_root,
        },
        slot_number: inputs.slot_number,
        target_gas_limit: inputs.target_gas_limit,
    };
    let custody_columns = CustodyColumns::from_indices(custody.0.iter().copied());
    // Heze (Bogota): V5, whose attributes carry the inclusion list
    // transactions the payload must satisfy.
    let started = match &prepared.inclusion_list_transactions {
        Some(inclusion_list_transactions) => {
            let attributes = PayloadAttributesV5 {
                v4: attributes,
                inclusion_list_transactions: inclusion_list_transactions.clone(),
            };
            engine
                .forkchoice_updated_v5_with_attributes(&forkchoice, &attributes, custody_columns)
                .await
                .map(|(status, payload_id)| (status.status, payload_id))
        }
        None => {
            engine
                .forkchoice_updated_v4_with_attributes(&forkchoice, &attributes, custody_columns)
                .await
        }
    };
    let (status, payload_id) = started.map_err(|err| {
        warn!(%err, "forkchoiceUpdated with payload attributes failed");
        ApiError::ServiceUnavailable("the execution client did not start building")
    })?;
    let Some(payload_id) = payload_id else {
        warn!(status = ?status.status, "The execution client declined to build a payload");
        return Err(ApiError::ServiceUnavailable(
            "the execution client declined to build a payload",
        ));
    };
    engine.get_payload_v6(payload_id).await.map_err(|err| {
        warn!(%err, "getPayloadV6 failed");
        ApiError::ServiceUnavailable("the execution client did not return a payload")
    })
}

/// The pure half: the pooled operations and the built payload into a block and
/// its envelope.
#[allow(clippy::too_many_arguments)]
fn assemble(
    config: &Config,
    prepared: &Prepared,
    built: BuiltGloasPayload,
    execution_requests: ExecutionRequests,
    candidates: Vec<containers::electra::Attestation>,
    messages: Vec<containers::gloas::PayloadAttestationMessage>,
    sync_candidate: Option<SyncAggregate>,
    randao_reveal: BlsSignature,
    graffiti: Bytes32,
) -> Result<GloasProduced, ApiError> {
    let Prepared {
        state,
        head_root,
        head_slot,
        parent_requests,
        ..
    } = prepared;
    let attestations = pack_gloas_attestations(state, candidates);
    let payload_attestations =
        pack_payload_attestations(state, *head_root, *head_slot, messages, config);
    let commitments = built.blobs_bundle.commitments;
    // Verified exactly as `process_sync_aggregate` will check it, against the
    // state the block is built on; a candidate that fails becomes the empty
    // aggregate rather than a block the chain would refuse.
    let sync_aggregate = sync_candidate.map_or_else(empty_sync_aggregate, |candidate| {
        verified_sync_aggregate(state, candidate)
    });
    let has_sync_aggregate = sync_aggregate != empty_sync_aggregate();
    let inputs = |attestations, payload_attestations, sync_aggregate| GloasBlockInputs {
        sync_aggregate,
        randao_reveal,
        graffiti,
        attestations,
        payload_attestations,
        parent_execution_requests: parent_requests.clone(),
        execution_payload: built.execution_payload.clone(),
        blob_kzg_commitments: commitments.clone(),
        execution_requests: execution_requests.clone(),
        inclusion_list_bits: prepared.inclusion_list_bits.clone(),
    };
    let operations = attestations.len() + payload_attestations.len();
    let attempt = inputs(attestations, payload_attestations, sync_aggregate);
    match assemble_gloas_block(state, attempt, config) {
        Ok(produced) => Ok(produced),
        // The packers check every operation's signature against this state, and
        // the sync aggregate was verified above, so this should not happen; but
        // a block without them still earns the proposal, and one that fails to build earns nothing.
        Err(err) if operations > 0 || has_sync_aggregate => {
            warn!(slot = state.slot(), %err, "Block with operations failed to build; retrying without");
            let bare = inputs(Vec::new(), Vec::new(), empty_sync_aggregate());
            assemble_gloas_block(state, bare, config)
                .map_err(|_| ApiError::Internal("the block failed to build"))
        }
        Err(_) => Err(ApiError::Internal("the block failed to build")),
    }
}

/// [`assemble`] for a block that commits to a builder's bid: no payload, no
/// envelope. `process_block` on the block enforces the bid's own rules.
#[allow(clippy::too_many_arguments)]
fn assemble_on_bid(
    config: &Config,
    prepared: &Prepared,
    signed_bid: SignedExecutionPayloadBid,
    candidates: Vec<containers::electra::Attestation>,
    messages: Vec<containers::gloas::PayloadAttestationMessage>,
    sync_candidate: Option<SyncAggregate>,
    randao_reveal: BlsSignature,
    graffiti: Bytes32,
) -> Result<BeaconBlock, ApiError> {
    let Prepared {
        state,
        head_root,
        head_slot,
        parent_requests,
        ..
    } = prepared;
    let attestations = pack_gloas_attestations(state, candidates);
    let payload_attestations =
        pack_payload_attestations(state, *head_root, *head_slot, messages, config);
    // Verified exactly as `process_sync_aggregate` will check it, against the
    // state the block is built on, like the self-build's.
    let sync_aggregate = sync_candidate.map_or_else(empty_sync_aggregate, |candidate| {
        verified_sync_aggregate(state, candidate)
    });
    let has_sync_aggregate = sync_aggregate != empty_sync_aggregate();
    let inputs = |attestations, payload_attestations, sync_aggregate| GloasBidBlockInputs {
        randao_reveal,
        graffiti,
        attestations,
        payload_attestations,
        parent_execution_requests: parent_requests.clone(),
        signed_bid: signed_bid.clone(),
        sync_aggregate,
    };
    let operations = attestations.len() + payload_attestations.len();
    let attempt = inputs(attestations, payload_attestations, sync_aggregate);
    match assemble_gloas_block_on_bid(state, attempt, config) {
        Ok(block) => Ok(block),
        Err(err) if operations > 0 || has_sync_aggregate => {
            warn!(slot = state.slot(), %err, "Bid block with operations failed to build; retrying without");
            let bare = inputs(Vec::new(), Vec::new(), empty_sync_aggregate());
            assemble_gloas_block_on_bid(state, bare, config)
                .map_err(|_| ApiError::Internal("the block failed to build"))
        }
        Err(_) => Err(ApiError::Internal("the block failed to build")),
    }
}

/// `GET /eth/v1/validator/execution_payload_envelopes/{slot}/{beacon_block_root}`.
async fn get_envelope(
    Path((slot, block_root)): Path<(String, String)>,
    Extension(cache): Extension<PayloadCache>,
    headers: HeaderMap,
) -> Response {
    let Ok(slot) = slot.parse::<Slot>() else {
        return ApiError::BadRequest("invalid slot").into_response();
    };
    let Some(block_root) = parse_root(&block_root) else {
        return ApiError::BadRequest("invalid beacon_block_root").into_response();
    };
    let Some(cached) = cache.get(slot, block_root) else {
        return ApiError::NotFound("execution payload envelope not available for the slot")
            .into_response();
    };
    let accept = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok());
    let response = match Encoding::from_accept(accept) {
        Encoding::Ssz => ssz_response(cached.envelope.to_ssz()),
        Encoding::Json => crate::json_response(serde_json::json!({
            "version": ForkName::Gloas.as_str(),
            "data": cached.envelope,
        })),
    };
    with_consensus_version(response, ForkName::Gloas)
}

fn parse_root(text: &str) -> Option<H256> {
    let bytes: [u8; 32] = hex::decode(text.strip_prefix("0x")?)
        .ok()?
        .try_into()
        .ok()?;
    Some(H256(bytes))
}

/// The block and its post-state for `root`, waiting up to `timeout` for the
/// chain actor to import them.
async fn wait_for_block(
    store: &Store,
    root: H256,
    timeout: Duration,
) -> Option<(containers::SignedBeaconBlock, Arc<BeaconState>)> {
    let deadline = Instant::now() + timeout;
    loop {
        if let (Ok(Some(block)), Ok(Some(state))) =
            (store.get_signed_block(&root), store.get_state(&root))
        {
            return Some((block, state));
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(BLOCK_POLL_INTERVAL).await;
    }
}

/// `POST /eth/v1/beacon/execution_payload_envelopes`, SSZ only.
///
/// The envelope must fulfill the bid of a gloas block this node holds (waiting
/// briefly for the block, see [`BLOCK_WAIT`]), carry the proposer's signature
/// under `DOMAIN_BEACON_BUILDER`, and come with the blobs the bid commits to,
/// from the body (`Eth-Blob-Data-Included: true`) or from what
/// `produceBlockV4` cached (`false`). The data columns are built from the
/// blobs, checked against the bid's commitments, and gossiped with the
/// envelope.
async fn post_envelope(
    State(store): State<Store>,
    Extension(p2p): Extension<RpcToP2PRef>,
    Extension(cache): Extension<PayloadCache>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    post_envelope_waiting(&store, &p2p, &cache, &headers, &body, BLOCK_WAIT).await
}

async fn post_envelope_waiting(
    store: &Store,
    p2p: &RpcToP2PRef,
    cache: &PayloadCache,
    headers: &HeaderMap,
    body: &[u8],
    block_wait: Duration,
) -> Response {
    if !consensus_version(headers).is_some_and(ForkName::is_gloas_or_later) {
        return ApiError::BadRequest("Eth-Consensus-Version must be gloas or heze").into_response();
    }
    let encoding = match BodyEncoding::from_headers(headers) {
        Ok(encoding) => encoding,
        Err(err) => return err.into_response(),
    };
    let blob_data_included = match headers
        .get("eth-blob-data-included")
        .and_then(|value| value.to_str().ok())
    {
        Some("true") => true,
        Some("false") => false,
        _ => {
            return ApiError::BadRequest("Eth-Blob-Data-Included must be true or false")
                .into_response();
        }
    };
    let (signed, supplied) = if blob_data_included {
        match encoding.decode::<GloasSignedEnvelopeContents>(body) {
            Some(contents) => (
                contents.signed_execution_payload_envelope,
                Some((
                    contents
                        .blobs
                        .iter()
                        .map(|blob| blob.to_vec())
                        .collect::<Vec<_>>(),
                    contents.kzg_proofs.to_vec(),
                )),
            ),
            None => {
                return ApiError::BadRequest(
                    "the body is not a gloas SignedExecutionPayloadEnvelopeContents",
                )
                .into_response();
            }
        }
    } else {
        match encoding.decode::<SignedExecutionPayloadEnvelope>(body) {
            Some(signed) => (signed, None),
            None => {
                return ApiError::BadRequest(
                    "the body is not a gloas SignedExecutionPayloadEnvelope",
                )
                .into_response();
            }
        }
    };

    let block_root = signed.message.beacon_block_root;
    let Some((block, post_state)) = wait_for_block(store, block_root, block_wait).await else {
        return ApiError::BadRequest("unknown block: the envelope's block is not held")
            .into_response();
    };
    let containers::SignedBeaconBlock::Gloas(block) = block else {
        return ApiError::BadRequest("the envelope's block is not a gloas block").into_response();
    };
    let block_slot = block.message.slot;
    let bid = block.message.body.signed_execution_payload_bid.message;
    if signed.message.builder_index != bid.builder_index
        || signed.message.payload.block_hash != bid.block_hash
    {
        return ApiError::BadRequest("the envelope does not fulfill the block's bid")
            .into_response();
    }

    let (blobs, cell_proofs) = match supplied {
        Some(supplied) => supplied,
        None => match cache.get(block_slot, block_root) {
            Some(cached) => (cached.blobs, cached.cell_proofs),
            None if bid.blob_kzg_commitments.is_empty() => (Vec::new(), Vec::new()),
            None => {
                return ApiError::BadRequest(
                    "no cached blobs for the block: send them with Eth-Blob-Data-Included: true",
                )
                .into_response();
            }
        },
    };
    if blobs.len() != bid.blob_kzg_commitments.len() {
        return ApiError::BadRequest("the blobs do not match the bid's commitments")
            .into_response();
    }

    // Signature and the columns' proofs are CPU-bound; off the runtime.
    let commitments: Vec<_> = bid.blob_kzg_commitments.iter().copied().collect();
    let envelope_for_check = signed.clone();
    let checked = tokio::task::spawn_blocking(move || {
        if !verify_execution_payload_envelope_signature(&post_state, &envelope_for_check)
            .map_err(|_| ApiError::BadRequest("the envelope's signer is unknown"))?
        {
            return Err(ApiError::BadRequest("invalid envelope signature"));
        }
        let sidecars = if blobs.is_empty() {
            Vec::new()
        } else {
            let sidecars = gloas_data_column_sidecars(block_root, block_slot, &blobs, &cell_proofs)
                .map_err(|_| {
                    ApiError::BadRequest("the blobs and proofs do not form valid columns")
                })?;
            let verified = sidecars.iter().all(|sidecar| {
                gloas_verify_data_column_sidecar(sidecar, &commitments)
                    && gloas_verify_data_column_sidecar_kzg_proofs(sidecar, &commitments)
                        .unwrap_or(false)
            });
            if !verified {
                return Err(ApiError::BadRequest(
                    "the data columns do not verify against the bid's commitments",
                ));
            }
            sidecars
        };
        Ok(sidecars)
    })
    .await;
    let sidecars = match checked {
        Ok(Ok(sidecars)) => sidecars,
        Ok(Err(err)) => return err.into_response(),
        Err(_) => return ApiError::Internal("verifying the envelope failed").into_response(),
    };

    let sidecars: Vec<DataColumnSidecar> =
        sidecars.into_iter().map(DataColumnSidecar::Gloas).collect();
    if p2p
        .publish_execution_payload_envelope(Box::new(signed), sidecars)
        .is_err()
    {
        return ApiError::Internal("the network actor is not running").into_response();
    }
    StatusCode::OK.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{RecordingNetwork, beacon_store_with_config};
    use axum::{body::Body, http::Request};
    use ethlambda_state_transition::beacon::gloas_block_production::test_support::{
        config, post_state, produce as produce_block, sign_block, sign_envelope, state_to_build_on,
    };
    use ethlambda_state_transition::beacon::helpers::test_state::with_signing_validators_at;
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    async fn respond(app: Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap_or_default())
    }

    /// A store holding a fulu head, under a schedule that puts every slot at
    /// gloas: the head is behind the fork, as on a node running across it.
    fn gloas_scheduled_store() -> (Store, Slot) {
        let state = with_signing_validators_at(ForkName::Fulu, 64);
        let head_slot = state.slot();
        let (store, _root) = beacon_store_with_config(state, config());
        (store, head_slot)
    }

    fn produce_app(store: Store, engine: Option<EngineClient>) -> Router {
        routes()
            .with_state(store)
            .layer(Extension(engine))
            .layer(Extension(SharedSyncCommitteePool::default()))
            .layer(Extension(SharedPayloadAttestationPool::default()))
            .layer(Extension(SharedBuilderMarket::default()))
            .layer(Extension(FeeRecipients::default()))
            .layer(Extension(NodeCustodyColumns::default()))
            .layer(Extension(OwnVersion(Arc::new(ClientVersionV1 {
                code: "LA".to_string(),
                name: "ethlambda".to_string(),
                version: "ethlambda/test".to_string(),
                commit: "0x3c4d7e8f".to_string(),
            }))))
    }

    fn produce_request(slot: Slot, query: &str, body: &str) -> Request<Body> {
        Request::post(format!(
            "/eth/v4/validator/blocks/{slot}?randao_reveal=0x{}{query}",
            "00".repeat(96)
        ))
        .header("eth-consensus-version", "gloas")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
    }

    #[tokio::test]
    async fn an_envelope_over_the_default_body_limit_is_not_a_413() {
        let (store, _) = gloas_scheduled_store();
        let network: RpcToP2PRef = std::sync::Arc::new(RecordingNetwork::default());
        let app = routes().with_state(store).layer(Extension(network));
        let request = Request::post("/eth/v1/beacon/execution_payload_envelopes")
            .header("eth-consensus-version", "gloas")
            .header("eth-blob-data-included", "true")
            .header(header::CONTENT_TYPE, crate::SSZ_CONTENT_TYPE)
            .body(Body::from(vec![0u8; 3 * 1024 * 1024]))
            .unwrap();
        let (status, _) = respond(app, request).await;
        assert_ne!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    const EMPTY_CONFIG: &str = r#"{"min_bid":"0","builder_boost_factor":"0","builders":[]}"#;

    #[tokio::test]
    async fn producing_a_pre_gloas_slot_is_a_400_even_with_no_execution_client() {
        let state = with_signing_validators_at(ForkName::Fulu, 64);
        let head_slot = state.slot();
        // The default schedule never reaches gloas.
        let (store, _root) = beacon_store_with_config(state, Config::mainnet());
        let app = produce_app(store, None);
        let (status, json) = respond(
            app,
            produce_request(head_slot + 1, "&include_payload=true", EMPTY_CONFIG),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["message"], "this endpoint serves gloas slots only");
    }

    #[tokio::test]
    async fn producing_without_an_execution_client_is_a_503() {
        let (store, head_slot) = gloas_scheduled_store();
        let app = produce_app(store, None);
        let (status, _) = respond(
            app,
            produce_request(head_slot + 1, "&include_payload=true", EMPTY_CONFIG),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn a_missing_include_payload_or_an_undecodable_body_is_a_400() {
        let (store, head_slot) = gloas_scheduled_store();
        let (status, _) = respond(
            produce_app(store.clone(), None),
            produce_request(head_slot + 1, "", EMPTY_CONFIG),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, json) = respond(
            produce_app(store.clone(), None),
            produce_request(head_slot + 1, "&include_payload=true", "not a config"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["message"], "the body is not a BuilderConfig");

        // A wrong fork header is refused too.
        let request = Request::post(format!(
            "/eth/v4/validator/blocks/{}?randao_reveal=0x{}&include_payload=true",
            head_slot + 1,
            "00".repeat(96)
        ))
        .header("eth-consensus-version", "fulu")
        .body(Body::from(EMPTY_CONFIG))
        .unwrap();
        let (status, _) = respond(produce_app(store, None), request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn a_builder_config_decodes_as_json_or_ssz() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            decode_builder_config(&headers, EMPTY_CONFIG.as_bytes())
                .unwrap()
                .builders
                .len(),
            0
        );
        assert!(decode_builder_config(&headers, b"{}").is_err());

        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(crate::SSZ_CONTENT_TYPE),
        );
        // min_bid, boost factor, then the offset of an empty builders list.
        let mut ssz = vec![0u8; 16];
        ssz.extend_from_slice(&20u32.to_le_bytes());
        assert_eq!(
            decode_builder_config(&headers, &ssz)
                .unwrap()
                .builders
                .len(),
            0
        );
        assert!(decode_builder_config(&headers, &ssz[..19]).is_err());
    }

    #[test]
    fn the_cache_keeps_the_current_and_previous_slot_only() {
        let cache = PayloadCache::default();
        let state = state_to_build_on();
        let produced = produce_block(&state, true, Vec::new()).unwrap();
        let entry = CachedPayload {
            envelope: produced.envelope,
            blobs: Vec::new(),
            cell_proofs: Vec::new(),
        };
        for slot in [10, 11, 12] {
            cache.insert(slot, H256::repeat_byte(slot as u8), entry.clone());
        }
        assert!(cache.get(10, H256::repeat_byte(10)).is_none());
        assert!(cache.get(11, H256::repeat_byte(11)).is_some());
        assert!(cache.get(12, H256::repeat_byte(12)).is_some());
        // The root is part of the key: a re-orged block gets no envelope.
        assert!(cache.get(12, H256::repeat_byte(99)).is_none());
    }

    /// A store holding the built block and its post-state (the way the chain
    /// actor stores an import), with the gloas schedule.
    fn store_with_block(
        state: &BeaconState,
        produced: &GloasProduced,
        signature: BlsSignature,
    ) -> (Store, H256, BeaconState) {
        let (mut store, _anchor) = beacon_store_with_config(state.clone(), config());
        let root = produced.block.hash_tree_root();
        let post = post_state(state, &produced.block);
        store
            .insert_signed_block(
                root,
                containers::SignedBeaconBlock::Gloas(containers::gloas::SignedBeaconBlock {
                    message: produced.block.clone(),
                    signature,
                }),
            )
            .unwrap();
        store.insert_state(root, post.clone()).unwrap();
        (store, root, post)
    }

    fn envelope_request(included: Option<&str>, body: Vec<u8>) -> (HeaderMap, Vec<u8>) {
        let mut headers = HeaderMap::new();
        headers.insert("eth-consensus-version", HeaderValue::from_static("gloas"));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(crate::SSZ_CONTENT_TYPE),
        );
        if let Some(included) = included {
            headers.insert(
                "eth-blob-data-included",
                HeaderValue::from_str(included).unwrap(),
            );
        }
        (headers, body)
    }

    /// The same as [`envelope_request`] with a JSON body, which is what teku's
    /// validator client posts.
    fn json_envelope_request(included: Option<&str>, body: Vec<u8>) -> (HeaderMap, Vec<u8>) {
        let (mut headers, body) = envelope_request(included, body);
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        (headers, body)
    }

    #[tokio::test]
    async fn an_envelope_is_accepted_as_json_exactly_as_it_is_as_ssz() {
        let state = state_to_build_on();
        let produced = produced_without_blobs(&state);
        let signature = sign_block(&state, &produced.block);
        let (store, _root, post) = store_with_block(&state, &produced, signature);
        let signed = signed_envelope(&post, &produced);
        let wait = Duration::from_millis(100);

        let mut published = Vec::new();
        for json in [false, true] {
            let network = Arc::new(RecordingNetwork::default());
            let p2p: RpcToP2PRef = network.clone();
            let (headers, body) = if json {
                json_envelope_request(Some("false"), serde_json::to_vec(&signed).unwrap())
            } else {
                envelope_request(Some("false"), signed.to_ssz())
            };
            let response = post_envelope_waiting(
                &store,
                &p2p,
                &PayloadCache::default(),
                &headers,
                &body,
                wait,
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK, "json: {json}");
            published.push(network.envelopes.lock().unwrap().clone());
        }
        assert_eq!(published[0].len(), 1);
        assert_eq!(published[0], published[1]);

        // The same refusals: a forged signature, and a body that is not an envelope.
        let network = Arc::new(RecordingNetwork::default());
        let p2p: RpcToP2PRef = network.clone();
        let mut forged = signed.clone();
        forged.signature =
            sign_envelope(&post, produced.block.proposer_index + 1, &produced.envelope);
        let (headers, body) =
            json_envelope_request(Some("false"), serde_json::to_vec(&forged).unwrap());
        let response = post_envelope_waiting(
            &store,
            &p2p,
            &PayloadCache::default(),
            &headers,
            &body,
            wait,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let (headers, body) = json_envelope_request(Some("false"), b"{\"message\": 1}".to_vec());
        let response = post_envelope_waiting(
            &store,
            &p2p,
            &PayloadCache::default(),
            &headers,
            &body,
            wait,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(network.envelopes.lock().unwrap().is_empty());
    }

    /// A produced block with no blobs, so the envelope needs no columns.
    fn produced_without_blobs(state: &BeaconState) -> GloasProduced {
        use ethlambda_state_transition::beacon::gloas_block_production::{
            GloasBlockInputs, assemble_gloas_block, gloas_payload_inputs,
            test_support::{payload_for, randao_reveal},
        };
        let requests = ExecutionRequests::default();
        let inputs = gloas_payload_inputs(state, true, &requests, &config()).unwrap();
        assemble_gloas_block(
            state,
            GloasBlockInputs {
                sync_aggregate:
                    ethlambda_state_transition::beacon::block_production::empty_sync_aggregate(),
                randao_reveal: randao_reveal(state),
                graffiti: Bytes32::ZERO,
                attestations: Vec::new(),
                payload_attestations: Vec::new(),
                parent_execution_requests: requests,
                execution_payload: payload_for(&inputs),
                blob_kzg_commitments: Vec::new(),
                execution_requests: ExecutionRequests::default(),
                inclusion_list_bits: None,
            },
            &config(),
        )
        .unwrap()
    }

    /// A sync aggregate of committee `positions` signing `root` under the
    /// state's own domain for slot `state.slot - 1`, the check
    /// `process_sync_aggregate` holds a block's aggregate to.
    fn sync_aggregate_over(state: &BeaconState, root: H256, positions: &[usize]) -> SyncAggregate {
        use ethlambda_state_transition::beacon::helpers::test_state::sign_for;
        let previous_slot = state.slot() - 1;
        let domain = get_domain(
            state,
            constants::DOMAIN_SYNC_COMMITTEE,
            Some(compute_epoch_at_slot(previous_slot)),
        );
        let signing_root = compute_signing_root(root, domain);
        let (committee, _) = state.sync_committees().unwrap();
        let mut aggregate = empty_sync_aggregate();
        let mut signatures = Vec::new();
        for &position in positions {
            let pubkey = committee.pubkeys[position];
            let index = (0..64)
                .find(|&index| state.validator(index).unwrap().pubkey == pubkey)
                .expect("the committee is drawn from the registry");
            signatures.push(sign_for(index as usize, signing_root));
            aggregate.sync_committee_bits.set(position, true).unwrap();
        }
        aggregate.sync_committee_signature = bls::aggregate(&signatures).unwrap();
        aggregate
    }

    /// `assemble` over the fixture's build state with `candidate` pooled.
    fn assembled_with(state: &BeaconState, candidate: Option<SyncAggregate>) -> GloasProduced {
        use ethlambda_state_transition::beacon::gloas_block_production::test_support::{
            payload_for, randao_reveal,
        };
        let requests = ExecutionRequests::default();
        let inputs = gloas_payload_inputs(state, true, &requests, &config()).unwrap();
        let built = BuiltGloasPayload {
            execution_payload: payload_for(&inputs),
            block_value: Default::default(),
            blobs_bundle: Default::default(),
            execution_requests: Vec::new(),
            should_override_builder: false,
        };
        let prepared = Prepared {
            state: state.clone(),
            inputs,
            proposer: get_beacon_proposer_index(state).unwrap(),
            head_root: H256::repeat_byte(5),
            head_slot: state.slot() - 1,
            parent_requests: requests.clone(),
            preferences: None,
            inclusion_list_bits: None,
            inclusion_list_transactions: None,
        };
        assemble(
            &config(),
            &prepared,
            built,
            requests,
            Vec::new(),
            Vec::new(),
            candidate,
            randao_reveal(state),
            Bytes32::ZERO,
        )
        .unwrap()
    }

    #[test]
    fn a_pooled_sync_aggregate_is_included_and_a_wrong_one_becomes_the_empty_aggregate() {
        use ethlambda_state_transition::beacon::{
            gloas_block_production::test_support::state_to_build_on,
            helpers::accessors::get_block_root_at_slot,
        };
        let state = state_to_build_on();
        let parent_root = get_block_root_at_slot(&state, state.slot() - 1).unwrap();

        let good = sync_aggregate_over(&state, parent_root, &[0, 1, 2]);
        let produced = assembled_with(&state, Some(good.clone()));
        assert_eq!(produced.block.body.sync_aggregate, good);

        let wrong = sync_aggregate_over(&state, H256::repeat_byte(1), &[0, 1, 2]);
        let produced = assembled_with(&state, Some(wrong));
        assert_eq!(produced.block.body.sync_aggregate, empty_sync_aggregate());

        let produced = assembled_with(&state, None);
        assert_eq!(produced.block.body.sync_aggregate, empty_sync_aggregate());
    }

    /// A block built on a builder's bid carries the pooled sync aggregate, and
    /// a wrong one becomes the empty aggregate, as for a self-build.
    #[test]
    fn a_block_built_on_a_bid_carries_the_pooled_sync_aggregate() {
        use ethlambda_state_transition::beacon::{
            builder_market::test_support::{gloas_state_with_builder, sign_bid},
            gloas_block_production::test_support::{PARENT_BLOCK_HASH, randao_reveal},
            helpers::accessors::{get_block_root_at_slot, get_current_epoch, get_randao_mix},
        };
        let parent = gloas_state_with_builder(0, 100_000_000_000, 0);
        let state = advance_to_slot(&parent, parent.slot() + 1, &config()).unwrap();
        let parent_root = get_block_root_at_slot(&state, state.slot() - 1).unwrap();
        let bid = sign_bid(
            &state,
            containers::gloas::ExecutionPayloadBid {
                parent_block_hash: H256::repeat_byte(PARENT_BLOCK_HASH),
                parent_block_root: state.latest_block_header().hash_tree_root(),
                block_hash: H256::repeat_byte(0x33),
                prev_randao: get_randao_mix(&state, get_current_epoch(&state)),
                gas_limit: 30_000_000,
                builder_index: 0,
                slot: state.slot(),
                value: 7,
                ..Default::default()
            },
            0,
        );
        let requests = ExecutionRequests::default();
        let inputs = gloas_payload_inputs(&state, true, &requests, &config()).unwrap();
        let prepared = Prepared {
            state: state.clone(),
            inputs,
            proposer: get_beacon_proposer_index(&state).unwrap(),
            head_root: H256::repeat_byte(5),
            head_slot: state.slot() - 1,
            parent_requests: requests,
            preferences: None,
            inclusion_list_bits: None,
            inclusion_list_transactions: None,
        };
        let build = |candidate| {
            assemble_on_bid(
                &config(),
                &prepared,
                bid.clone(),
                Vec::new(),
                Vec::new(),
                candidate,
                randao_reveal(&state),
                Bytes32::ZERO,
            )
            .unwrap()
        };

        let good = sync_aggregate_over(&state, parent_root, &[0, 1, 2]);
        assert_eq!(build(Some(good.clone())).body.sync_aggregate, good);
        let wrong = sync_aggregate_over(&state, H256::repeat_byte(1), &[0, 1, 2]);
        assert_eq!(
            build(Some(wrong)).body.sync_aggregate,
            empty_sync_aggregate()
        );
        assert_eq!(build(None).body.sync_aggregate, empty_sync_aggregate());
    }

    fn signed_envelope(
        post: &BeaconState,
        produced: &GloasProduced,
    ) -> SignedExecutionPayloadEnvelope {
        SignedExecutionPayloadEnvelope {
            message: produced.envelope.clone(),
            signature: sign_envelope(post, produced.block.proposer_index, &produced.envelope),
        }
    }

    #[tokio::test]
    async fn a_signed_envelope_for_a_held_block_is_gossiped() {
        let state = state_to_build_on();
        let produced = produced_without_blobs(&state);
        let signature = sign_block(&state, &produced.block);
        let (store, _root, post) = store_with_block(&state, &produced, signature);
        let signed = signed_envelope(&post, &produced);

        let network = Arc::new(RecordingNetwork::default());
        let p2p: RpcToP2PRef = network.clone();
        let (headers, body) = envelope_request(Some("false"), signed.to_ssz());
        let response = post_envelope_waiting(
            &store,
            &p2p,
            &PayloadCache::default(),
            &headers,
            &body,
            Duration::from_millis(100),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let published = network.envelopes.lock().unwrap();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].0, signed);
        assert!(published[0].1.is_empty());
    }

    #[tokio::test]
    async fn an_envelope_for_a_block_that_arrives_late_waits_for_it() {
        let state = state_to_build_on();
        let produced = produced_without_blobs(&state);
        let signature = sign_block(&state, &produced.block);
        let (store, root, post) = store_with_block(&state, &produced, signature);
        let signed = signed_envelope(&post, &produced);
        // The block is imported only after the request is already waiting:
        // an empty store to start with, filled in by a second task.
        let (empty_store, _anchor) = beacon_store_with_config(state.clone(), config());
        let mut late_store = empty_store.clone();
        let block = store.get_signed_block(&root).unwrap().unwrap();
        let importer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            late_store.insert_signed_block(root, block).unwrap();
            late_store.insert_state(root, post).unwrap();
        });

        let network = Arc::new(RecordingNetwork::default());
        let p2p: RpcToP2PRef = network.clone();
        let (headers, body) = envelope_request(Some("false"), signed.to_ssz());
        let response = post_envelope_waiting(
            &empty_store,
            &p2p,
            &PayloadCache::default(),
            &headers,
            &body,
            Duration::from_secs(5),
        )
        .await;
        importer.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(network.envelopes.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn an_envelope_for_an_unknown_block_is_a_400_after_the_wait() {
        let state = state_to_build_on();
        let produced = produced_without_blobs(&state);
        let post = post_state(&state, &produced.block);
        let signed = signed_envelope(&post, &produced);
        let (store, _anchor) = beacon_store_with_config(state, config());

        let network = Arc::new(RecordingNetwork::default());
        let p2p: RpcToP2PRef = network.clone();
        let (headers, body) = envelope_request(Some("false"), signed.to_ssz());
        let started = Instant::now();
        let response = post_envelope_waiting(
            &store,
            &p2p,
            &PayloadCache::default(),
            &headers,
            &body,
            Duration::from_millis(150),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(started.elapsed() >= Duration::from_millis(150));
        assert!(network.envelopes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_bad_signature_a_wrong_bid_and_a_wrong_media_type_are_refused() {
        let state = state_to_build_on();
        let produced = produced_without_blobs(&state);
        let signature = sign_block(&state, &produced.block);
        let (store, _root, post) = store_with_block(&state, &produced, signature);
        let network = Arc::new(RecordingNetwork::default());
        let p2p: RpcToP2PRef = network.clone();
        let cache = PayloadCache::default();
        let wait = Duration::from_millis(100);

        // Signed by someone else.
        let mut forged = signed_envelope(&post, &produced);
        forged.signature =
            sign_envelope(&post, produced.block.proposer_index + 1, &produced.envelope);
        let (headers, body) = envelope_request(Some("false"), forged.to_ssz());
        let response = post_envelope_waiting(&store, &p2p, &cache, &headers, &body, wait).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // A payload other than the one the bid commits to.
        let mut other = signed_envelope(&post, &produced);
        other.message.payload.block_hash = H256::repeat_byte(0x77);
        let (headers, body) = envelope_request(Some("false"), other.to_ssz());
        let response = post_envelope_waiting(&store, &p2p, &cache, &headers, &body, wait).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Any other content type is a 415 (JSON is accepted, see
        // `an_envelope_is_accepted_as_json_exactly_as_it_is_as_ssz`), and SSZ
        // bytes labelled JSON are not a JSON envelope.
        let signed = signed_envelope(&post, &produced);
        let (mut headers, body) = envelope_request(Some("false"), signed.to_ssz());
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        let response = post_envelope_waiting(&store, &p2p, &cache, &headers, &body, wait).await;
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let (mut headers, body) = envelope_request(Some("false"), signed.to_ssz());
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let response = post_envelope_waiting(&store, &p2p, &cache, &headers, &body, wait).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // The blob-data header is required.
        let (headers, body) = envelope_request(None, signed.to_ssz());
        let response = post_envelope_waiting(&store, &p2p, &cache, &headers, &body, wait).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(network.envelopes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_cached_envelope_is_served_for_its_slot_and_root_only() {
        let state = state_to_build_on();
        let produced = produced_without_blobs(&state);
        let root = produced.block.hash_tree_root();
        let slot = produced.block.slot;
        let (store, _anchor) = beacon_store_with_config(state, config());
        let app = routes().with_state(store);
        // The route layer's own cache cannot be reached from here, so the
        // handler is exercised directly through a router with a seeded one.
        let cache = PayloadCache::default();
        cache.insert(
            slot,
            root,
            CachedPayload {
                envelope: produced.envelope.clone(),
                blobs: Vec::new(),
                cell_proofs: Vec::new(),
            },
        );
        let seeded = Router::new()
            .route(
                "/eth/v1/validator/execution_payload_envelopes/{slot}/{beacon_block_root}",
                get(get_envelope),
            )
            .layer(Extension(cache));
        let uri = format!(
            "/eth/v1/validator/execution_payload_envelopes/{slot}/0x{}",
            hex::encode(root.0)
        );
        let (status, json) = respond(
            seeded.clone(),
            Request::get(&uri).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["version"], "gloas");
        assert_eq!(
            json["data"]["builder_index"],
            constants::BUILDER_INDEX_SELF_BUILD.to_string()
        );

        let ssz_request = Request::get(&uri)
            .header(header::ACCEPT, "application/octet-stream")
            .body(Body::empty())
            .unwrap();
        let response = seeded.clone().oneshot(ssz_request).await.unwrap();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes.as_ref(), produced.envelope.to_ssz().as_slice());

        let other = format!(
            "/eth/v1/validator/execution_payload_envelopes/{slot}/0x{}",
            "11".repeat(32)
        );
        let (status, _) = respond(seeded, Request::get(other).body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        // The unseeded production router answers 404 too.
        let (status, _) = respond(app, Request::get(&uri).body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// A block carrying one real blob, its signed envelope, and the body the
    /// stateless form of the publish endpoint takes.
    struct WithBlob {
        state: BeaconState,
        produced: GloasProduced,
        blob: Vec<u8>,
        proofs: Vec<KzgProof>,
    }

    fn with_blob() -> WithBlob {
        use ethlambda_state_transition::beacon::{
            gloas_block_production::test_support::{payload_for, randao_reveal},
            kzg::{blob_to_kzg_commitment, compute_cells_and_kzg_proofs},
        };
        let state = state_to_build_on();
        let mut blob = vec![0u8; ethlambda_types::beacon::preset::BYTES_PER_BLOB];
        for (i, element) in blob.chunks_mut(32).enumerate() {
            element[31] = (i % 100) as u8;
        }
        let commitment = blob_to_kzg_commitment(&blob).unwrap();
        let (_, proofs) = compute_cells_and_kzg_proofs(&blob).unwrap();
        let requests = ExecutionRequests::default();
        let inputs = gloas_payload_inputs(&state, true, &requests, &config()).unwrap();
        let produced = assemble_gloas_block(
            &state,
            GloasBlockInputs {
                sync_aggregate:
                    ethlambda_state_transition::beacon::block_production::empty_sync_aggregate(),
                randao_reveal: randao_reveal(&state),
                graffiti: Bytes32::ZERO,
                attestations: Vec::new(),
                payload_attestations: Vec::new(),
                parent_execution_requests: requests,
                execution_payload: payload_for(&inputs),
                blob_kzg_commitments: vec![commitment],
                execution_requests: ExecutionRequests::default(),
                inclusion_list_bits: None,
            },
            &config(),
        )
        .unwrap();
        WithBlob {
            state,
            produced,
            blob,
            proofs: proofs.to_vec(),
        }
    }

    #[tokio::test]
    async fn json_envelope_contents_carry_the_blobs_and_are_checked_like_ssz() {
        let WithBlob {
            state,
            produced,
            blob,
            proofs,
        } = with_blob();
        let signature = sign_block(&state, &produced.block);
        let (store, _root, post) = store_with_block(&state, &produced, signature);
        let signed = signed_envelope(&post, &produced);
        let wait = Duration::from_millis(100);
        let contents = |blob: &[u8]| GloasSignedEnvelopeContents {
            signed_execution_payload_envelope: signed.clone(),
            kzg_proofs: CellKzgProofs::try_from(proofs.clone()).unwrap(),
            blobs: blobs_list(vec![blob.to_vec()]).unwrap(),
        };
        let send = |network: Arc<RecordingNetwork>, contents: GloasSignedEnvelopeContents| {
            let store = store.clone();
            async move {
                let p2p: RpcToP2PRef = network;
                let (headers, body) =
                    json_envelope_request(Some("true"), serde_json::to_vec(&contents).unwrap());
                post_envelope_waiting(
                    &store,
                    &p2p,
                    &PayloadCache::default(),
                    &headers,
                    &body,
                    wait,
                )
                .await
            }
        };

        let network = Arc::new(RecordingNetwork::default());
        let response = send(network.clone(), contents(&blob)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            network.envelopes.lock().unwrap()[0].1.len(),
            ethlambda_types::beacon::preset::NUMBER_OF_COLUMNS
        );

        let mut tampered = blob.clone();
        tampered[63] ^= 1;
        let rejected = Arc::new(RecordingNetwork::default());
        let response = send(rejected.clone(), contents(&tampered)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(rejected.envelopes.lock().unwrap().is_empty());
    }

    #[test]
    fn the_block_and_envelope_contents_round_trip_through_json() {
        let WithBlob {
            state,
            produced,
            blob,
            proofs,
        } = with_blob();
        let signature = sign_block(&state, &produced.block);
        let (_store, _root, post) = store_with_block(&state, &produced, signature);
        let signed = signed_envelope(&post, &produced);
        let contents = GloasSignedEnvelopeContents {
            signed_execution_payload_envelope: signed,
            kzg_proofs: CellKzgProofs::try_from(proofs.clone()).unwrap(),
            blobs: blobs_list(vec![blob.clone()]).unwrap(),
        };
        let back: GloasSignedEnvelopeContents =
            serde_json::from_slice(&serde_json::to_vec(&contents).unwrap()).unwrap();
        assert_eq!(back, contents);

        let block_contents = GloasBlockContents {
            block: produced.block.clone(),
            execution_payload_envelope: produced.envelope.clone(),
            kzg_proofs: CellKzgProofs::try_from(proofs).unwrap(),
            blobs: blobs_list(vec![blob]).unwrap(),
        };
        let back: GloasBlockContents =
            serde_json::from_slice(&serde_json::to_vec(&block_contents).unwrap()).unwrap();
        assert_eq!(back, block_contents);
    }

    #[tokio::test]
    async fn an_envelope_with_blobs_gossips_every_column_and_a_tampered_blob_is_refused() {
        let WithBlob {
            state,
            produced,
            blob,
            proofs,
        } = with_blob();
        let signature = sign_block(&state, &produced.block);
        let (store, root, post) = store_with_block(&state, &produced, signature);
        let signed = signed_envelope(&post, &produced);
        let wait = Duration::from_millis(100);
        let contents = |blob: &[u8]| GloasSignedEnvelopeContents {
            signed_execution_payload_envelope: signed.clone(),
            kzg_proofs: CellKzgProofs::try_from(proofs.clone()).unwrap(),
            blobs: blobs_list(vec![blob.to_vec()]).unwrap(),
        };

        // Stateless: the blobs travel with the envelope.
        let network = Arc::new(RecordingNetwork::default());
        let p2p: RpcToP2PRef = network.clone();
        let (headers, body) = envelope_request(Some("true"), contents(&blob).to_ssz());
        let response = post_envelope_waiting(
            &store,
            &p2p,
            &PayloadCache::default(),
            &headers,
            &body,
            wait,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        {
            let published = network.envelopes.lock().unwrap();
            assert_eq!(published.len(), 1);
            assert_eq!(
                published[0].1.len(),
                ethlambda_types::beacon::preset::NUMBER_OF_COLUMNS
            );
        }

        // A different blob under the same proofs does not verify.
        let mut tampered = blob.clone();
        tampered[63] ^= 1;
        let rejected = Arc::new(RecordingNetwork::default());
        let p2p: RpcToP2PRef = rejected.clone();
        let (headers, body) = envelope_request(Some("true"), contents(&tampered).to_ssz());
        let response = post_envelope_waiting(
            &store,
            &p2p,
            &PayloadCache::default(),
            &headers,
            &body,
            wait,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Stateful: nothing cached means a 400, and the cached blobs are used when present.
        let (headers, body) = envelope_request(Some("false"), signed.to_ssz());
        let response = post_envelope_waiting(
            &store,
            &p2p,
            &PayloadCache::default(),
            &headers,
            &body,
            wait,
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let cache = PayloadCache::default();
        cache.insert(
            produced.block.slot,
            root,
            CachedPayload {
                envelope: produced.envelope.clone(),
                blobs: vec![blob],
                cell_proofs: proofs,
            },
        );
        let response = post_envelope_waiting(&store, &p2p, &cache, &headers, &body, wait).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(rejected.envelopes.lock().unwrap().len(), 1);
    }
}

#[cfg(test)]
#[path = "builder_market_tests.rs"]
mod builder_market_tests;
