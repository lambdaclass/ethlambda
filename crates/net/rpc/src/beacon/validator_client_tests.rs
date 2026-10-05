//! `ethlambda validator`'s own HTTP client, driven against this node's Beacon
//! API over a real socket.
//!
//! The endpoint tests elsewhere check each answer against the spec; this checks
//! the two ends agree on the wire. A field this node names differently from what
//! the client parses, a number left unquoted, or a status the client does not
//! expect would each pass every endpoint test here and still leave the client
//! unable to attest.

use std::sync::Arc;

use axum::Extension;
use ethlambda_blockchain::{SyncStatusController, metrics::SyncStatus};
use ethlambda_network_api::RpcToP2PRef;
use ethlambda_state_transition::beacon::helpers::{
    accessors::get_domain,
    fulu::initialize_proposer_lookahead,
    test_state::{sign_for, with_signing_validators_at},
};
use ethlambda_state_transition::beacon::payload_attestation_pool::SharedPayloadAttestationPool;
use ethlambda_storage::Store;
use ethlambda_types::{
    beacon::{
        constants::DOMAIN_BEACON_ATTESTER,
        containers::BeaconState,
        fork::ForkName,
        preset,
        primitives::{BlsPubkey, BlsSignature},
        signing::{compute_epoch_at_slot, compute_signing_root, compute_start_slot_at_epoch},
    },
    primitives::HashTreeRoot as _,
};
use ethlambda_validator::{
    Error,
    beacon_node::{
        AggregateKind, BeaconNodeApi, BlockRequest, SignedAggregates,
        dto::{
            AttestationDataOutDto, CommitteeSubscriptionDto, ProposerPreparationDto,
            SingleAttestationDto, encode_hex,
        },
        http::HttpBeaconNode,
    },
};

use crate::test_utils::{RecordingNetwork, beacon_store_at, idle_engine};

const COUNT: usize = 64;

/// The version this node reports for itself, as `ethlambda beacon` builds it.
fn own_version() -> ethlambda_engine::types::ClientVersionV1 {
    ethlambda_engine::types::ClientVersionV1 {
        code: "LA".to_string(),
        name: "ethlambda".to_string(),
        version: "ethlambda/test".to_string(),
        commit: "0x3c4d7e8f".to_string(),
    }
}

/// A fulu head state at the first slot of the wall clock's current epoch, with
/// its proposer lookahead filled in, served over HTTP on an ephemeral port,
/// by a node with no execution client.
async fn serve() -> (HttpBeaconNode, BeaconState, Arc<RecordingNetwork>) {
    serve_with_engine(None).await
}

async fn serve_with_engine(
    engine: Option<ethlambda_engine::EngineClient>,
) -> (HttpBeaconNode, BeaconState, Arc<RecordingNetwork>) {
    let (client, state, network, _, _) = serve_at(engine).await;
    (client, state, network)
}

/// [`serve_with_engine`], also handing back the served store, for a test that
/// changes what the node knows while it runs. It is a handle onto the same
/// store the router reads.
async fn serve_with_store(
    engine: Option<ethlambda_engine::EngineClient>,
) -> (HttpBeaconNode, BeaconState, Arc<RecordingNetwork>, Store) {
    let (client, state, network, _, store) = serve_at(engine).await;
    (client, state, network, store)
}

/// [`serve_with_store`], also naming the socket it listens on.
async fn serve_at(
    engine: Option<ethlambda_engine::EngineClient>,
) -> (
    HttpBeaconNode,
    BeaconState,
    Arc<RecordingNetwork>,
    std::net::SocketAddr,
    Store,
) {
    let mut state = with_signing_validators_at(ForkName::Fulu, COUNT);
    let (probe, _) = beacon_store_at(state.clone());
    let wall_epoch = compute_epoch_at_slot(crate::beacon::node::wall_slot(&probe));
    let lookahead = {
        let BeaconState::Fulu(fulu) = &mut state else {
            unreachable!("built as fulu")
        };
        fulu.slot = compute_start_slot_at_epoch(wall_epoch);
        initialize_proposer_lookahead(&state).unwrap()
    };
    // The builder leaves the sync committee as a placeholder, which
    // `process_sync_aggregate` rejects when a block is built on this state.
    let sync_committee =
        ethlambda_state_transition::beacon::helpers::altair::get_next_sync_committee(&state)
            .unwrap();
    let BeaconState::Fulu(fulu) = &mut state else {
        unreachable!("built as fulu")
    };
    fulu.proposer_lookahead = lookahead.try_into().unwrap();
    fulu.current_sync_committee = sync_committee.clone();
    fulu.next_sync_committee = sync_committee;

    let (mut store, _root) = beacon_store_at(state.clone());
    // A block built on this head names the head block's real root as its
    // parent, which the fixture's placeholder anchor block does not have:
    // keep the state under that root too, as a real anchor would be.
    let advanced = ethlambda_state_transition::beacon::block_production::advance_to_slot(
        &state,
        state.slot() + 1,
        &ethlambda_types::beacon::config::Config::mainnet(),
    )
    .unwrap();
    let parent_root = advanced.latest_block_header().hash_tree_root();
    store.insert_state(parent_root, state.clone()).unwrap();
    let (client, network, _pool, address) = spawn_server(store.clone(), engine).await;
    (client, state, network, address, store)
}

/// Serve `store` through the router the real server builds, over a socket on an
/// ephemeral port, and connect this crate's client to it. Also hands back the
/// payload attestation pool the router fills and the socket it listens on.
async fn spawn_server(
    mut store: Store,
    engine: Option<ethlambda_engine::EngineClient>,
) -> (
    HttpBeaconNode,
    Arc<RecordingNetwork>,
    SharedPayloadAttestationPool,
    std::net::SocketAddr,
) {
    // The store's clock, which the aggregate conditions read the current epoch
    // from, as the chain actor's ticks would have set it.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    store.set_time_ms(now_ms).unwrap();
    let network = Arc::new(RecordingNetwork::default());
    let p2p: RpcToP2PRef = network.clone();
    let payload_pool = SharedPayloadAttestationPool::default();
    let router = crate::build_beacon_api_router(store, "ethlambda/test", "peer".into())
        .layer(Extension(SyncStatusController::new(SyncStatus::Synced)))
        .layer(Extension(p2p))
        .layer(Extension(payload_pool.clone()))
        .layer(Extension(crate::CustodyColumns(Vec::new())))
        .layer(Extension(crate::beacon::validator::FeeRecipients::default()))
        .layer(Extension(engine))
        .layer(Extension(crate::beacon::graffiti::OwnVersion(Arc::new(
            own_version(),
        ))));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await });

    let client = HttpBeaconNode::new(format!("http://{address}")).unwrap();
    (client, network, payload_pool, address)
}

/// One slot of an attester's work, in the order `ethlambda validator` does it.
///
/// The node has an execution client, since it refuses attestation data
/// without one. None of these calls reach it.
#[tokio::test]
async fn the_validator_client_can_attest_through_this_node() {
    let (client, state, network) = serve_with_engine(idle_engine()).await;
    let slot = state.slot();
    let epoch = compute_epoch_at_slot(slot);

    client.genesis().await.expect("genesis");
    client
        .spec()
        .await
        .expect("the client reads this node's spec");
    assert!(
        !client.is_optimistic_or_syncing().await.unwrap(),
        "a synced node with no optimistic block must be signable against"
    );

    let pubkeys: Vec<BlsPubkey> = (0..COUNT as u64)
        .map(|index| state.validator(index).unwrap().pubkey)
        .collect();
    let entries = client.validator_indices(&pubkeys).await.unwrap();
    assert_eq!(entries.len(), COUNT);
    let indices: Vec<u64> = entries.iter().map(|entry| entry.index).collect();

    let proposers = client.proposer_duties(epoch).await.unwrap();
    assert_eq!(proposers.duties.len(), preset::SLOTS_PER_EPOCH as usize);

    let attesters = client.attester_duties(epoch, &indices).await.unwrap();
    assert_eq!(
        attesters.duties.len(),
        COUNT,
        "everyone attests once per epoch"
    );

    let subscriptions: Vec<CommitteeSubscriptionDto> = attesters
        .duties
        .iter()
        .map(|duty| CommitteeSubscriptionDto {
            validator_index: duty.validator_index,
            committee_index: duty.committee_index,
            committees_at_slot: duty.committees_at_slot,
            slot: duty.slot,
            is_aggregator: false,
        })
        .collect();
    client.subscribe_committees(&subscriptions).await.unwrap();
    let preparation = ProposerPreparationDto {
        validator_index: 0,
        fee_recipient: format!("0x{}", "de".repeat(20)),
    };
    client
        .prepare_beacon_proposer(&[preparation])
        .await
        .unwrap();

    // The attestation data is checked by the client itself before it signs.
    let data = client.attestation_data(slot, ForkName::Fulu).await.unwrap();
    let domain = get_domain(&state, DOMAIN_BEACON_ATTESTER, Some(data.target.epoch));
    let signing_root = compute_signing_root(data.hash_tree_root(), domain);
    let data_dto = AttestationDataOutDto::from(&data);
    let attestations: Vec<SingleAttestationDto> = attesters
        .duties
        .iter()
        .filter(|duty| duty.slot == slot)
        .map(|duty| SingleAttestationDto {
            committee_index: duty.committee_index,
            attester_index: duty.validator_index,
            data: data_dto.clone(),
            signature: encode_hex(&sign_for(duty.validator_index as usize, signing_root).0),
        })
        .collect();
    assert!(!attestations.is_empty(), "someone attests at the head slot");

    let accepted = client
        .submit_attestations(&attestations, "fulu")
        .await
        .unwrap();
    assert_eq!(accepted, attestations.len());
    assert_eq!(network.published.lock().unwrap().len(), attestations.len());

    // Aggregation, as an aggregator of the head slot's first committee: the
    // aggregate of what was just submitted, then the signed aggregate back.
    let duty = attesters
        .duties
        .iter()
        .find(|duty| duty.slot == slot)
        .expect("someone attests at the head slot");
    let aggregate = client
        .aggregate_attestation(slot, data.hash_tree_root(), duty.committee_index)
        .await
        .unwrap();
    assert_eq!(aggregate.fork, ForkName::Fulu);
    let voters = attestations
        .iter()
        .filter(|attestation| attestation.committee_index == duty.committee_index)
        .count();
    let AggregateKind::Electra(attestation) = aggregate.attestation else {
        panic!("a fulu slot's aggregate is electra's container");
    };
    let bits = (0..duty.committee_length as usize)
        .filter(|&i| attestation.aggregation_bits.get(i).unwrap())
        .count();
    assert_eq!(bits, voters);

    let signed = signed_aggregate(&state, duty.validator_index, attestation);
    client
        .publish_aggregates(ForkName::Fulu, &SignedAggregates::Electra(vec![signed]))
        .await
        .unwrap();
    assert_eq!(network.aggregates.lock().unwrap().len(), 1);
}

/// A signed aggregate from `aggregator`, as phase0's `validator.md`
/// ("Construct aggregate") builds it. Every member of these small committees
/// is an aggregator, so any member's selection proof selects it.
fn signed_aggregate(
    state: &BeaconState,
    aggregator: u64,
    aggregate: ethlambda_types::beacon::containers::electra::Attestation,
) -> ethlambda_types::beacon::containers::electra::SignedAggregateAndProof {
    use ethlambda_types::beacon::constants::{DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_SELECTION_PROOF};
    use ethlambda_types::beacon::containers::electra::{
        AggregateAndProof, SignedAggregateAndProof,
    };
    let slot = aggregate.data.slot;
    let epoch = compute_epoch_at_slot(slot);
    let selection_domain = get_domain(state, DOMAIN_SELECTION_PROOF, Some(epoch));
    let selection_proof = sign_for(
        aggregator as usize,
        compute_signing_root(slot.hash_tree_root(), selection_domain),
    );
    let message = AggregateAndProof {
        aggregator_index: aggregator,
        aggregate,
        selection_proof,
    };
    let domain = get_domain(state, DOMAIN_AGGREGATE_AND_PROOF, Some(epoch));
    let signature = sign_for(
        aggregator as usize,
        compute_signing_root(message.hash_tree_root(), domain),
    );
    SignedAggregateAndProof { message, signature }
}

/// On a head its execution client has not validated, the node refuses to hand
/// out a vote, and the client reads that refusal the way it reads a node still
/// syncing: as one to fail over from, and not as a malformed answer. Both ways
/// of noticing agree, the per-request 503 and `/node/syncing`.
#[tokio::test]
async fn an_optimistic_head_is_one_the_client_will_not_attest_through() {
    let (client, state, _, mut store) = serve_with_store(idle_engine()).await;
    let (_slot, head_root) = store.beacon_head().expect("the anchor is the head");
    store.insert_beacon_optimistic_root(head_root, state.slot());

    let err = client
        .attestation_data(state.slot(), ForkName::Fulu)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::BeaconNodeSyncing), "got {err:?}");
    assert!(err.is_retryable());
    assert!(client.is_optimistic_or_syncing().await.unwrap());

    store.remove_beacon_optimistic_root(head_root);
    client
        .attestation_data(state.slot(), ForkName::Fulu)
        .await
        .expect("a validated head is attested to again");
    assert!(!client.is_optimistic_or_syncing().await.unwrap());
}

/// Without an execution client to build a payload with, block production
/// answers 503, which the client reads as a node it can fail over from rather
/// than a malformed answer.
#[tokio::test]
async fn block_production_without_an_execution_client_is_retryable() {
    let (client, state, _) = serve().await;
    let request = BlockRequest {
        slot: state.slot() + 1,
        fork: ForkName::Fulu,
        proposer_index: 0,
        randao_reveal: Default::default(),
        graffiti: Default::default(),
    };
    let err = client.produce_block(&request).await.unwrap_err();
    assert!(matches!(err, Error::BeaconNodeSyncing), "got {err:?}");
    assert!(err.is_retryable());
}

/// A blob whose every field element is below the BLS modulus: the first byte
/// of each 32-byte element is zero, the rest are `seed`-derived.
fn valid_blob(seed: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; preset::BYTES_PER_BLOB];
    for (i, element) in bytes.chunks_mut(32).enumerate() {
        element[1] = seed;
        element[2] = i as u8;
        element[3] = (i >> 8) as u8;
    }
    bytes
}

/// A stand-in execution client: `forkchoiceUpdated` with attributes answers a
/// payload id, and `getPayload` a payload that extends the requested head with
/// exactly the requested attributes, which is all a real one's payload has to
/// agree with for the block to verify. Answers both generations: V3/V5 for
/// fulu and V4/V6 (`PayloadAttributesV4`, `ExecutionPayloadV4`) for gloas.
///
/// The fulu bundle carries `blob_count` valid blobs with their commitments and
/// cell proofs (flattened blob by blob, as `BlobsBundleV2` does).
async fn fake_execution_client(blob_count: usize) -> ethlambda_engine::EngineClient {
    fake_execution_client_with(blob_count, None).await
}

/// [`fake_execution_client`] whose gloas payloads carry `blob`, with its real
/// commitment and cell proofs, in the blobs bundle.
async fn fake_execution_client_with_blob(blob: Option<Vec<u8>>) -> ethlambda_engine::EngineClient {
    fake_execution_client_with(0, blob).await
}

async fn fake_execution_client_with(
    blob_count: usize,
    blob: Option<Vec<u8>>,
) -> ethlambda_engine::EngineClient {
    use axum::{Json, routing::post};
    use ethlambda_state_transition::beacon::kzg;
    use std::sync::Mutex;

    let hex_of = |bytes: &[u8]| format!("0x{}", hex::encode(bytes));
    let blobs: Vec<Vec<u8>> = (0..blob_count)
        .map(|seed| valid_blob(seed as u8 + 1))
        .collect();
    let commitments: Vec<String> = blobs
        .iter()
        .map(|blob| hex_of(kzg::blob_to_kzg_commitment(blob).unwrap().as_ref()))
        .collect();
    let proofs: Vec<String> = blobs
        .iter()
        .flat_map(|blob| {
            let (_, proofs) = kzg::compute_cells_and_kzg_proofs(blob).unwrap();
            proofs
                .iter()
                .map(|proof| hex_of(proof.as_ref()))
                .collect::<Vec<_>>()
        })
        .collect();
    let blobs: Vec<String> = blobs.iter().map(|blob| hex_of(blob)).collect();
    let blob_gas_used = format!("0x{:x}", blob_count * 131072);
    let bundle = match &blob {
        None => serde_json::json!({ "commitments": [], "proofs": [], "blobs": [] }),
        Some(blob) => {
            let commitment = kzg::blob_to_kzg_commitment(blob).unwrap();
            let (_, proofs) = kzg::compute_cells_and_kzg_proofs(blob).unwrap();
            serde_json::json!({
                "commitments": [encode_hex(&commitment.0)],
                "proofs": proofs.iter().map(|proof| encode_hex(&proof.0)).collect::<Vec<_>>(),
                "blobs": [encode_hex(blob)],
            })
        }
    };
    let requested: Arc<Mutex<Option<serde_json::Value>>> = Arc::default();
    let handler = move |Json(request): Json<serde_json::Value>| {
        let requested = requested.clone();
        let (commitments, proofs, blobs) = (commitments.clone(), proofs.clone(), blobs.clone());
        let blob_gas_used = blob_gas_used.clone();
        let bundle = bundle.clone();
        async move {
            let payload = |attributes: &serde_json::Value, gas_limit: serde_json::Value| {
                serde_json::json!({
                    "parentHash": attributes["parentHash"],
                    "feeRecipient": attributes["suggestedFeeRecipient"],
                    "stateRoot": format!("0x{}", "00".repeat(32)),
                    "receiptsRoot": format!("0x{}", "00".repeat(32)),
                    "logsBloom": format!("0x{}", "00".repeat(256)),
                    "prevRandao": attributes["prevRandao"],
                    "blockNumber": "0x1",
                    "gasLimit": gas_limit,
                    "gasUsed": "0x0",
                    "timestamp": attributes["timestamp"],
                    "extraData": "0x",
                    "baseFeePerGas": "0x7",
                    "blockHash": format!("0x{}", "ee".repeat(32)),
                    "transactions": [],
                    "withdrawals": attributes["withdrawals"],
                    "blobGasUsed": "0x0",
                    "excessBlobGas": "0x0",
                })
            };
            let result = match request["method"].as_str() {
                Some("engine_forkchoiceUpdatedV3" | "engine_forkchoiceUpdatedV4") => {
                    let mut attributes = request["params"][1].clone();
                    attributes["parentHash"] = request["params"][0]["headBlockHash"].clone();
                    *requested.lock().unwrap() = Some(attributes);
                    serde_json::json!({
                        "payloadStatus": { "status": "VALID", "latestValidHash": null },
                        "payloadId": "0x0000000000000001",
                    })
                }
                Some("engine_getPayloadV5") => {
                    let attributes = requested.lock().unwrap().clone().unwrap();
                    let mut v5_payload = payload(&attributes, "0x1c9c380".into());
                    v5_payload["blobGasUsed"] = blob_gas_used.clone().into();
                    serde_json::json!({
                        "executionPayload": v5_payload,
                        "blockValue": "0x2a",
                        "blobsBundle": { "commitments": commitments, "proofs": proofs, "blobs": blobs },
                        "shouldOverrideBuilder": false,
                        "executionRequests": [],
                    })
                }
                Some("engine_getClientVersionV1") => serde_json::json!([{
                    "code": "RH",
                    "name": "reth",
                    "version": "v1.0.0",
                    "commit": "0x1a2b5c6d",
                }]),
                Some("engine_getPayloadV6") => {
                    let attributes = requested.lock().unwrap().clone().unwrap();
                    let mut execution_payload =
                        payload(&attributes, attributes["targetGasLimit"].clone());
                    execution_payload["blockAccessList"] = "0xc0".into();
                    execution_payload["slotNumber"] = attributes["slotNumber"].clone();
                    serde_json::json!({
                        "executionPayload": execution_payload,
                        "blockValue": "0x2a",
                        "blobsBundle": bundle,
                        "shouldOverrideBuilder": false,
                        "executionRequests": [],
                    })
                }
                _ => serde_json::Value::Null,
            };
            Json(serde_json::json!({ "jsonrpc": "2.0", "id": request["id"], "result": result }))
        }
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = axum::Router::new().route("/", post(handler));
    tokio::spawn(async move { axum::serve(listener, router).await });
    ethlambda_engine::EngineClient::new(
        format!("http://{address}"),
        ethlambda_engine::JwtSecret::new([0x0f; 32]),
    )
    .unwrap()
}

/// A proposer's slot through this node up to the produced block: the block
/// from this node's execution client (with `blob_count` blobs), and what a
/// validator client needs to sign it.
async fn produce_for_proposer(blob_count: usize) -> Proposal {
    produce_with_pool(blob_count, |_store, _state| {}).await
}

/// [`produce_for_proposer`], after `fill_pool` has put operations into the
/// node's pool.
async fn produce_with_pool(
    blob_count: usize,
    fill_pool: impl FnOnce(&ethlambda_storage::Store, &BeaconState),
) -> Proposal {
    use ethlambda_state_transition::beacon::{
        block_production::advance_to_slot, helpers::accessors::get_beacon_proposer_index,
    };
    use ethlambda_types::beacon::constants::{DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO};

    let (client, state, network, address, store) =
        serve_at(Some(fake_execution_client(blob_count).await)).await;
    fill_pool(&store, &state);
    let slot = state.slot() + 1;
    let advanced = advance_to_slot(
        &state,
        slot,
        &ethlambda_types::beacon::config::Config::mainnet(),
    )
    .unwrap();
    let proposer = get_beacon_proposer_index(&advanced).unwrap();
    let epoch = compute_epoch_at_slot(slot);
    let randao_domain = get_domain(&advanced, DOMAIN_RANDAO, Some(epoch));
    let randao_reveal = sign_for(
        proposer as usize,
        compute_signing_root(epoch.hash_tree_root(), randao_domain),
    );

    let mut graffiti = [0u8; 32];
    graffiti[..5].copy_from_slice(b"hello");
    let request = BlockRequest {
        slot,
        fork: ForkName::Fulu,
        proposer_index: proposer,
        randao_reveal,
        graffiti: ethlambda_types::primitives::H256(graffiti),
    };
    let produced = client.produce_block(&request).await.unwrap();
    assert_eq!(produced.slot(), slot);
    assert_eq!(produced.proposer_index(), proposer);
    // The proposer's text, then both clients' codes and commits: the
    // execution client's from `engine_getClientVersionV1`, this node's own.
    let mut expected = [0u8; 32];
    expected[..18].copy_from_slice(b"hello RH1a2bLA3c4d");
    assert_eq!(fulu_block(&produced).body.graffiti.0, expected);

    let block_domain = get_domain(&advanced, DOMAIN_BEACON_PROPOSER, Some(epoch));
    let signature = sign_for(
        proposer as usize,
        compute_signing_root(produced.block_root(), block_domain),
    );
    Proposal {
        client,
        network,
        produced,
        signature,
        address,
        slot,
        randao_reveal,
    }
}

/// The fulu block inside `produced`; these tests all propose at a fulu slot.
fn fulu_block(
    produced: &ethlambda_validator::beacon_node::block_contents::ProducedBlock,
) -> &ethlambda_types::beacon::containers::electra::BeaconBlock {
    use ethlambda_validator::beacon_node::block_contents::Contents;
    match &produced.contents {
        Contents::WithCellProofs { block, .. } | Contents::WithBlobProofs { block, .. } => block,
        Contents::Gloas { .. } => unreachable!("a fulu proposal"),
    }
}

/// What [`produce_for_proposer`] leaves a test to publish or probe with.
struct Proposal {
    client: HttpBeaconNode,
    network: Arc<RecordingNetwork>,
    produced: ethlambda_validator::beacon_node::block_contents::ProducedBlock,
    signature: BlsSignature,
    address: std::net::SocketAddr,
    slot: u64,
    randao_reveal: BlsSignature,
}

/// A proposer's slot through this node: the block produced from this node's
/// execution client, signed, and published back.
#[tokio::test]
async fn the_validator_client_can_propose_through_this_node() {
    let p = produce_for_proposer(0).await;
    let body = p.produced.into_signed_ssz(p.signature);
    p.client.publish_block(ForkName::Fulu, &body).await.unwrap();
    assert_eq!(p.network.blocks.lock().unwrap().len(), 1);
    assert!(p.network.sidecars.lock().unwrap().is_empty());
}

/// A voluntary exit in the node's pool rides in the block it produces. The
/// state sits at the wall clock's epoch, far past `SHARD_COMMITTEE_PERIOD`
/// since every validator is active from epoch 0, so the exit is valid.
#[tokio::test]
async fn a_pooled_exit_is_packed_into_the_produced_block() {
    use ethlambda_state_transition::beacon::helpers::misc::compute_domain;
    use ethlambda_types::beacon::{
        constants::DOMAIN_VOLUNTARY_EXIT, containers::shared, operation::BeaconOperation,
    };

    let mut expected = None;
    let p = produce_with_pool(0, |store, state| {
        let exit = shared::VoluntaryExit {
            epoch: compute_epoch_at_slot(state.slot()),
            validator_index: 5,
        };
        let domain = compute_domain(
            DOMAIN_VOLUNTARY_EXIT,
            store.config().capella_fork_version,
            state.genesis_validators_root(),
        );
        let signed = shared::SignedVoluntaryExit {
            message: exit,
            signature: sign_for(5, compute_signing_root(exit.hash_tree_root(), domain)),
        };
        store
            .operation_pool()
            .insert(BeaconOperation::VoluntaryExit(signed.clone()));
        expected = Some(signed);
    })
    .await;
    assert_eq!(
        fulu_block(&p.produced).body.voluntary_exits.to_vec(),
        vec![expected.unwrap()]
    );
}

#[tokio::test]
async fn the_validator_client_can_propose_a_blob_block_through_this_node() {
    use ethlambda_state_transition::beacon::fork_choice::verify_data_column_sidecar_inclusion_proof;

    let p = produce_for_proposer(2).await;
    assert_eq!(p.produced.blob_count(), 2);
    let body = p.produced.into_signed_ssz(p.signature);
    p.client.publish_block(ForkName::Fulu, &body).await.unwrap();
    assert_eq!(p.network.blocks.lock().unwrap().len(), 1);
    let sidecars = p.network.sidecars.lock().unwrap();
    assert_eq!(sidecars.len(), preset::NUMBER_OF_COLUMNS);
    // Built for a fulu block, so every one is fulu's shape.
    assert!(sidecars.iter().all(|sidecar| match sidecar {
        ethlambda_types::beacon::containers::DataColumnSidecar::Fulu(sidecar) => {
            verify_data_column_sidecar_inclusion_proof(sidecar)
        }
        ethlambda_types::beacon::containers::DataColumnSidecar::Gloas(_) => false,
    }));
}

/// Publishes `body` and asserts a 400 with nothing handed to the network.
async fn assert_publish_refused(p: &Proposal, body: &[u8]) {
    let result = p.client.publish_block(ForkName::Fulu, body).await;
    assert!(
        matches!(result, Err(Error::BeaconNodeStatus { status: 400, .. })),
        "{result:?}"
    );
    assert!(p.network.blocks.lock().unwrap().is_empty());
    assert!(p.network.sidecars.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_published_block_with_a_wrong_cell_proof_is_refused() {
    use crate::beacon::proposal::FuluSignedBlockContents;
    use libssz::{SszDecode as _, SszEncode as _};

    let p = produce_for_proposer(2).await;
    let body = p.produced.clone().into_signed_ssz(p.signature);
    let mut contents = FuluSignedBlockContents::from_ssz_bytes(&body).unwrap();
    contents.kzg_proofs.swap(0, 1);
    assert_publish_refused(&p, &contents.to_ssz()).await;
}

#[tokio::test]
async fn a_published_block_with_a_missing_cell_proof_is_refused() {
    use crate::beacon::proposal::FuluSignedBlockContents;
    use libssz::{SszDecode as _, SszEncode as _};

    let p = produce_for_proposer(2).await;
    let body = p.produced.clone().into_signed_ssz(p.signature);
    let mut contents = FuluSignedBlockContents::from_ssz_bytes(&body).unwrap();
    let mut proofs: Vec<_> = contents.kzg_proofs.iter().cloned().collect();
    proofs.pop();
    contents.kzg_proofs = proofs.try_into().unwrap();
    assert_publish_refused(&p, &contents.to_ssz()).await;
}

#[tokio::test]
async fn a_published_block_on_an_unknown_parent_is_refused() {
    use crate::beacon::proposal::FuluSignedBlockContents;
    use libssz::{SszDecode as _, SszEncode as _};

    let p = produce_for_proposer(0).await;
    let body = p.produced.clone().into_signed_ssz(p.signature);
    let mut contents = FuluSignedBlockContents::from_ssz_bytes(&body).unwrap();
    contents.signed_block.message.parent_root = ethlambda_types::primitives::H256([0xab; 32]);
    assert_publish_refused(&p, &contents.to_ssz()).await;
}

#[tokio::test]
async fn the_json_block_carries_its_blobs_and_cell_proofs_as_hex() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let p = produce_for_proposer(2).await;
    let randao = format!("0x{}", hex::encode(p.randao_reveal.0));
    let request = format!(
        "GET /eth/v3/validator/blocks/{}?randao_reveal={randao} HTTP/1.0\r\n\
         Accept: application/json\r\n\r\n",
        p.slot
    );
    let mut stream = tokio::net::TcpStream::connect(p.address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("HTTP/1.0 200"), "{head}");
    let json: serde_json::Value = serde_json::from_str(body).unwrap();
    let data = &json["data"];
    let blobs = data["blobs"].as_array().unwrap();
    let proofs = data["kzg_proofs"].as_array().unwrap();
    assert_eq!(blobs.len(), 2);
    assert_eq!(proofs.len(), 2 * preset::CELLS_PER_EXT_BLOB);
    assert!(
        blobs
            .iter()
            .chain(proofs)
            .all(|value| value.as_str().is_some_and(|text| text.starts_with("0x")))
    );
}

// ---------------------------------------------------------------------------
// Gloas
// ---------------------------------------------------------------------------

mod gloas {
    use std::time::Duration;

    use ethlambda_state_transition::beacon::{
        block_production::advance_to_slot,
        bls,
        constants::{DOMAIN_BEACON_BUILDER, DOMAIN_BEACON_PROPOSER, DOMAIN_PTC_ATTESTER},
        fork_choice::PayloadStatus,
        gloas_block_production::test_support::{config, parent_state, post_state},
        helpers::{
            accessors::get_beacon_proposer_index,
            gloas::{compute_ptc, get_ptc},
            test_state::secret_key_for,
        },
    };
    use ethlambda_types::beacon::{
        constants::BUILDER_INDEX_SELF_BUILD,
        containers::{SignedAggregateAndProof, SignedBeaconBlock, gloas as gloas_containers},
        primitives::Bytes32,
    };
    use ethlambda_validator::{
        beacon_node::dto::{ProposerDutyDto, PtcDutyDto},
        keys::ValidatorStore,
        payload_attestation::PayloadAttestationService,
        proposal::ProposalService,
        signing::SigningContext,
    };
    use tokio::sync::RwLock;

    use super::*;
    use crate::test_utils::{beacon_store_with_head_block, gloas_beacon_block};

    /// A gloas head state at slot 32 under [`config`] (gloas from epoch 0),
    /// with the proposer lookahead and sync committee a real registry gives it
    /// and every `ptc_window` entry computed, so the committees the node reads
    /// for the previous, current and next epoch are the real ones.
    fn head_state() -> BeaconState {
        let mut state = parent_state();
        let epoch = compute_epoch_at_slot(state.slot());
        let first_slot = compute_start_slot_at_epoch(epoch - 1);
        let cache =
            ethlambda_state_transition::beacon::helpers::accessors::CommitteeCache::default();
        let window: Vec<_> = (first_slot..first_slot + preset::PTC_WINDOW_LENGTH as u64)
            .map(|slot| compute_ptc(&state, slot, &cache).unwrap())
            .collect();
        let BeaconState::Gloas(inner) = &mut state else {
            unreachable!("built as gloas")
        };
        for (index, committee) in window.into_iter().enumerate() {
            inner.ptc_window[index] = committee;
        }
        // The fork the schedule puts the state in, so a signature made from
        // this client's schedule verifies against the state's own domain: the
        // builders leave `fork` zeroed, which no real state has.
        let schedule = config();
        inner.fork = ethlambda_types::beacon::containers::shared::Fork {
            previous_version: schedule.fork_version(ForkName::Fulu),
            current_version: schedule.fork_version(ForkName::Gloas),
            epoch: schedule.gloas_fork_epoch,
        };
        state
    }

    struct Served {
        client: HttpBeaconNode,
        state: BeaconState,
        network: Arc<RecordingNetwork>,
        payload_pool: SharedPayloadAttestationPool,
        store: Store,
        head_root: ethlambda_types::primitives::H256,
        context: Arc<SigningContext>,
    }

    /// The gloas head state served over HTTP, its head block a gloas block of
    /// the state's slot, on a clock where `clock_slot` is running now.
    async fn serve_gloas(
        clock_slot: u64,
        engine: Option<ethlambda_engine::EngineClient>,
    ) -> Served {
        let state = head_state();
        let block = gloas_beacon_block(
            state.slot(),
            Default::default(),
            Default::default(),
            Bytes32::repeat_byte(1),
        );
        // The root a block built on this state names as its parent: the
        // state's latest header, its state root filled in as the slot
        // transition does.
        let mut header = state.latest_block_header().clone();
        header.state_root = state.hash_tree_root();
        let head_root = header.hash_tree_root();
        let store =
            beacon_store_with_head_block(state.clone(), config(), block, head_root, clock_slot);
        let (client, network, payload_pool, _address) = spawn_server(store.clone(), engine).await;
        let genesis = client.genesis().await.expect("genesis");
        let spec = client
            .spec()
            .await
            .expect("the client reads this node's spec");
        let context = Arc::new(SigningContext {
            config: spec,
            genesis_validators_root: genesis.genesis_validators_root,
        });
        Served {
            client,
            state,
            network,
            payload_pool,
            store,
            head_root,
            context,
        }
    }

    /// A key store holding the test registry's secret for each of `indices`.
    fn keys_for(state: &BeaconState, indices: &[u64]) -> RwLock<ValidatorStore> {
        let mut keys = ValidatorStore::new();
        for &index in indices {
            let pubkey = keys
                .insert_secret("test", &secret_key_for(index as usize).to_bytes())
                .expect("the test secret is a valid key");
            assert_eq!(
                pubkey,
                state.validator(index).unwrap().pubkey,
                "the test registry's key for validator {index}"
            );
        }
        RwLock::new(keys)
    }

    /// One slot of a gloas attester's work: the data comes back without a
    /// committee index and names the payload signal, the gloas header goes out
    /// with the votes, and the aggregate is the gloas container.
    #[tokio::test]
    async fn the_validator_client_can_attest_and_aggregate_at_a_gloas_slot() {
        let Served {
            client,
            state,
            network,
            store,
            head_root,
            ..
        } = serve_gloas(32, idle_engine()).await;
        let slot = state.slot();
        let epoch = compute_epoch_at_slot(slot);
        assert_eq!(
            client.spec().await.unwrap().fork_at_epoch(epoch),
            ForkName::Gloas
        );

        let indices: Vec<u64> = (0..COUNT as u64).collect();
        let attesters = client.attester_duties(epoch, &indices).await.unwrap();
        assert_eq!(attesters.duties.len(), COUNT);

        // The attested block is the one of the requested slot: the payload
        // signal is 0.
        let data = client
            .attestation_data(slot, ForkName::Gloas)
            .await
            .unwrap();
        assert_eq!(data.slot, slot);
        assert_eq!(data.index, 0, "a same-slot vote carries no payload signal");
        // A vote for the next slot attests to the head block, now a slot
        // old: its signal is whether fork choice holds that block's payload
        // as full, and the client passes it on unchanged because it is signed.
        let later = client
            .attestation_data(slot + 1, ForkName::Gloas)
            .await
            .unwrap();
        assert_eq!(later.beacon_block_root, head_root);
        assert_eq!(later.index, 0, "no envelope was seen for the head block");
        store.set_head_payload_status(head_root, PayloadStatus::Full);
        let later = client
            .attestation_data(slot + 1, ForkName::Gloas)
            .await
            .unwrap();
        assert_eq!(later.index, 1);
        let domain = get_domain(&state, DOMAIN_BEACON_ATTESTER, Some(data.target.epoch));
        let signing_root = compute_signing_root(data.hash_tree_root(), domain);
        let data_dto = AttestationDataOutDto::from(&data);
        let attestations: Vec<SingleAttestationDto> = attesters
            .duties
            .iter()
            .filter(|duty| duty.slot == slot)
            .map(|duty| SingleAttestationDto {
                committee_index: duty.committee_index,
                attester_index: duty.validator_index,
                data: data_dto.clone(),
                signature: encode_hex(&sign_for(duty.validator_index as usize, signing_root).0),
            })
            .collect();
        assert!(!attestations.is_empty(), "someone attests at the head slot");

        let accepted = client
            .submit_attestations(&attestations, "gloas")
            .await
            .unwrap();
        assert_eq!(accepted, attestations.len());
        {
            let published = network.published.lock().unwrap();
            assert_eq!(published.len(), attestations.len());
            for (_, attestation) in published.iter() {
                assert_eq!(attestation.data, data);
            }
        }

        // Aggregation, as the first committee's aggregator would.
        let duty = attesters
            .duties
            .iter()
            .find(|duty| duty.slot == slot)
            .expect("someone attests at the head slot");
        let aggregate = client
            .aggregate_attestation(slot, data.hash_tree_root(), duty.committee_index)
            .await
            .unwrap();
        assert_eq!(aggregate.fork, ForkName::Gloas);
        let AggregateKind::Gloas(attestation) = aggregate.attestation else {
            panic!("a gloas slot's aggregate is gloas's container");
        };
        let voters = attestations
            .iter()
            .filter(|attestation| attestation.committee_index == duty.committee_index)
            .count();
        let bits = (0..duty.committee_length as usize)
            .filter(|&i| attestation.aggregation_bits.get(i).unwrap_or(false))
            .count();
        assert_eq!(bits, voters);

        let signed = signed_gloas_aggregate(&state, duty.validator_index, attestation);
        client
            .publish_aggregates(
                ForkName::Gloas,
                &SignedAggregates::Gloas(vec![signed.clone()]),
            )
            .await
            .unwrap();
        let recorded = network.aggregates.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0, SignedAggregateAndProof::Gloas(signed));
    }

    /// [`super::signed_aggregate`] for gloas, whose `Attestation` roots
    /// differently: the proof is signed over the gloas container.
    fn signed_gloas_aggregate(
        state: &BeaconState,
        aggregator: u64,
        aggregate: gloas_containers::Attestation,
    ) -> gloas_containers::SignedAggregateAndProof {
        use ethlambda_types::beacon::constants::{
            DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_SELECTION_PROOF,
        };
        let slot = aggregate.data.slot;
        let epoch = compute_epoch_at_slot(slot);
        let selection_domain = get_domain(state, DOMAIN_SELECTION_PROOF, Some(epoch));
        let selection_proof = sign_for(
            aggregator as usize,
            compute_signing_root(slot.hash_tree_root(), selection_domain),
        );
        let message = gloas_containers::AggregateAndProof {
            aggregator_index: aggregator,
            aggregate,
            selection_proof,
        };
        let domain = get_domain(state, DOMAIN_AGGREGATE_AND_PROOF, Some(epoch));
        let signature = sign_for(
            aggregator as usize,
            compute_signing_root(message.hash_tree_root(), domain),
        );
        gloas_containers::SignedAggregateAndProof { message, signature }
    }

    /// The committee's duties are the state's, no vote exists for a slot with
    /// no block, and the client's own votes (signed with its own key store and
    /// fork schedule) are accepted, gossiped and pooled.
    #[tokio::test]
    async fn the_validator_client_can_serve_on_the_payload_timeliness_committee() {
        let Served {
            client,
            state,
            network,
            payload_pool,
            head_root,
            context,
            ..
        } = serve_gloas(32, idle_engine()).await;
        let slot = state.slot();
        let epoch = compute_epoch_at_slot(slot);
        let config = config();

        // The duties are the first seat each validator holds in the epoch's
        // committees.
        let mut expected = std::collections::BTreeMap::new();
        for epoch_slot in compute_start_slot_at_epoch(epoch)..compute_start_slot_at_epoch(epoch + 1)
        {
            for member in get_ptc(&state, epoch_slot, &config).unwrap().iter() {
                expected.entry(*member).or_insert(epoch_slot);
            }
        }
        let indices: Vec<u64> = (0..COUNT as u64).collect();
        let duties = client.ptc_duties(epoch, &indices).await.unwrap();
        let served: std::collections::BTreeMap<u64, u64> = duties
            .duties
            .iter()
            .map(|duty| (duty.validator_index, duty.slot))
            .collect();
        assert_eq!(served, expected);
        for duty in &duties.duties {
            assert_eq!(
                duty.pubkey,
                encode_hex(&state.validator(duty.validator_index).unwrap().pubkey.0)
            );
        }
        // An epoch before gloas has no committee; this schedule has none.
        let next = client.ptc_duties(epoch + 1, &indices).await.unwrap();
        assert!(
            !next.duties.is_empty(),
            "the next epoch's window is readable"
        );

        // No block of the next slot, so no vote to cast; the head's own slot
        // has one, naming the head block.
        assert!(
            client
                .payload_attestation_data(slot + 1)
                .await
                .unwrap()
                .is_none()
        );
        let data = client
            .payload_attestation_data(slot)
            .await
            .unwrap()
            .expect("the head block's slot has data");
        assert_eq!(data.beacon_block_root, head_root);
        assert_eq!(data.slot, slot);
        assert!(!data.payload_present, "no envelope was seen");
        assert!(data.blob_data_available, "the bid commits to no blobs");

        // The real service: members of the slot's committee, signing with the
        // client's own schedule.
        let members: Vec<u64> = duties
            .duties
            .iter()
            .filter(|duty| duty.slot == slot)
            .map(|duty| duty.validator_index)
            .take(3)
            .collect();
        assert!(
            !members.is_empty(),
            "someone sits on the head slot's committee"
        );
        let keys = keys_for(&state, &members);
        let ptc_duties: Vec<PtcDutyDto> = duties
            .duties
            .iter()
            .filter(|duty| members.contains(&duty.validator_index))
            .cloned()
            .collect();
        let service = PayloadAttestationService::new(Arc::new(client), context);
        let accepted = service.attest(slot, &ptc_duties, &keys).await.unwrap();
        assert_eq!(accepted, members.len());

        // Recorded for gossip, pooled, and signed so that it verifies under the
        // state's own DOMAIN_PTC_ATTESTER.
        let recorded = network.payload_attestations.lock().unwrap().clone();
        assert_eq!(recorded.len(), members.len());
        let domain = get_domain(&state, DOMAIN_PTC_ATTESTER, Some(epoch));
        let signing_root = compute_signing_root(data.hash_tree_root(), domain);
        for message in &recorded {
            assert!(members.contains(&message.validator_index));
            assert_eq!(message.data, data);
            let pubkey = state.validator(message.validator_index).unwrap().pubkey;
            assert!(bls::verify(&pubkey, signing_root, &message.signature));
        }
        let pooled = payload_pool.lock().unwrap().all(Some(slot));
        assert_eq!(pooled.len(), members.len());
        for message in &recorded {
            assert!(pooled.contains(message));
        }
    }

    /// Insert the first block the node publishes into `store`, with its
    /// post-state, as the chain actor would on importing it: nothing in this
    /// harness does, and the envelope endpoint waits for the block.
    fn import_published_block(
        mut store: Store,
        network: Arc<RecordingNetwork>,
        parent: BeaconState,
    ) {
        tokio::spawn(async move {
            loop {
                let published = network.blocks.lock().unwrap().first().cloned();
                if let Some(SignedBeaconBlock::Gloas(signed)) = published {
                    let root = signed.message.hash_tree_root();
                    let post = post_state(&parent, &signed.message);
                    store
                        .insert_signed_block(root, SignedBeaconBlock::Gloas(signed))
                        .unwrap();
                    store.insert_state(root, post).unwrap();
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
    }

    /// A proposer's slot at gloas, through `ProposalService`: produceBlockV4
    /// with the payload, the block signed and published, the envelope signed
    /// and published. What the network was handed must verify against the
    /// state, with the proposer's key.
    async fn propose_through_the_service(blob: Option<Vec<u8>>) {
        let engine = fake_execution_client_with_blob(blob.clone()).await;
        let Served {
            client,
            state,
            network,
            store,
            context,
            ..
        } = serve_gloas(33, Some(engine)).await;
        let slot = state.slot() + 1;
        let epoch = compute_epoch_at_slot(slot);
        let advanced = advance_to_slot(&state, slot, &config()).unwrap();
        let proposer = get_beacon_proposer_index(&advanced).unwrap();
        let keys = keys_for(&state, &[proposer]);
        let pubkey = state.validator(proposer).unwrap().pubkey;
        import_published_block(store, network.clone(), advanced.clone());

        let service = ProposalService::new(
            Arc::new(client),
            context,
            Arc::new(
                ethlambda_validator::proposer_settings::ProposerSettings::new(
                    Bytes32::repeat_byte(0xab),
                    None,
                ),
            ),
        );
        let duty = ProposerDutyDto {
            pubkey: encode_hex(&pubkey.0),
            validator_index: proposer,
            slot,
        };
        service
            .propose(slot, &duty, &keys)
            .await
            .expect("the proposal goes through this node");

        // The block: gloas, the proposer's, and signed under the state's
        // proposer domain.
        let blocks = network.blocks.lock().unwrap().clone();
        assert_eq!(blocks.len(), 1);
        let SignedBeaconBlock::Gloas(signed_block) = &blocks[0] else {
            panic!("a gloas slot publishes a gloas block");
        };
        let block = &signed_block.message;
        assert_eq!(block.slot, slot);
        assert_eq!(block.proposer_index, proposer);
        let block_root = block.hash_tree_root();
        let block_domain = get_domain(&advanced, DOMAIN_BEACON_PROPOSER, Some(epoch));
        assert!(bls::verify(
            &pubkey,
            compute_signing_root(block_root, block_domain),
            &signed_block.signature
        ));

        // The envelope: for this block, a self-build, matching the bid it
        // reveals, and signed with the proposer's key under the builder domain.
        let envelopes = network.envelopes.lock().unwrap().clone();
        assert_eq!(envelopes.len(), 1, "the envelope reached the network");
        let (signed_envelope, sidecars) = &envelopes[0];
        let envelope = &signed_envelope.message;
        let bid = &block.body.signed_execution_payload_bid.message;
        assert_eq!(bid.builder_index, BUILDER_INDEX_SELF_BUILD);
        assert_eq!(envelope.builder_index, BUILDER_INDEX_SELF_BUILD);
        assert_eq!(envelope.beacon_block_root, block_root);
        assert_eq!(envelope.payload.block_hash, bid.block_hash);
        assert_eq!(envelope.payload.parent_hash, bid.parent_block_hash);
        assert_eq!(envelope.payload.gas_limit, bid.gas_limit);
        assert_eq!(envelope.payload.slot_number, slot);
        assert_eq!(
            envelope.execution_requests.hash_tree_root(),
            bid.execution_requests_root
        );
        let builder_domain = get_domain(&advanced, DOMAIN_BEACON_BUILDER, Some(epoch));
        assert!(bls::verify(
            &pubkey,
            compute_signing_root(envelope.hash_tree_root(), builder_domain),
            &signed_envelope.signature
        ));

        // With a blob: the bid commits to it and every column goes out with the
        // envelope (`Eth-Blob-Data-Included: true` carried the blobs).
        match blob {
            None => {
                assert!(bid.blob_kzg_commitments.is_empty());
                assert!(sidecars.is_empty());
            }
            Some(blob) => {
                let expected =
                    ethlambda_state_transition::beacon::kzg::blob_to_kzg_commitment(&blob).unwrap();
                assert_eq!(bid.blob_kzg_commitments.len(), 1);
                assert_eq!(bid.blob_kzg_commitments[0], expected);
                assert_eq!(sidecars.len(), preset::NUMBER_OF_COLUMNS);
            }
        }
    }

    #[tokio::test]
    async fn the_validator_client_can_propose_and_reveal_a_gloas_block() {
        propose_through_the_service(None).await;
    }

    #[tokio::test]
    async fn the_validator_client_can_propose_a_gloas_block_with_a_blob() {
        let mut blob = vec![0u8; preset::BYTES_PER_BLOB];
        for (i, element) in blob.chunks_mut(32).enumerate() {
            element[31] = (i % 100) as u8;
        }
        propose_through_the_service(Some(blob)).await;
    }
}
