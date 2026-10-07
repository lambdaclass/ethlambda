//! The builder market endpoints and `produceBlockV4`'s bid selection, driven
//! through the real router with a stand-in execution client.
//!
//! Tests that need the gossip rules, `dependent_root_at`, `bid_is_includable`
//! or `assemble_gloas_block_on_bid` exercise those functions as they are
//! implemented in `ethlambda-state-transition`; the ones that only check shapes
//! (headers, status codes, routing, idempotency against a primed market) do not
//! depend on them.

use std::sync::{Arc, Mutex};

use axum::{
    Extension, Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode},
};
use ethlambda_engine::{EngineClient, JwtSecret};
use ethlambda_network_api::RpcToP2PRef;
use ethlambda_state_transition::beacon::{
    block_production::advance_to_slot,
    builder_market::SharedBuilderMarket,
    gloas_block_production::test_support::{
        config as chain_config, parent_state, post_state, randao_reveal,
    },
    gossip::proposer_preferences::{dependent_root_at, proposer_preferences_domain},
    helpers::{
        accessors::get_domain,
        misc::compute_signing_root,
        test_state::{secret_key_for, sign_for},
    },
    payload_attestation_pool::SharedPayloadAttestationPool,
    sync_committee_pool::SharedSyncCommitteePool,
};
use ethlambda_storage::Store;
use ethlambda_types::{
    beacon::{
        constants::{
            BUILDER_INDEX_SELF_BUILD, DOMAIN_BEACON_BUILDER, FAR_FUTURE_EPOCH,
            PAYLOAD_BUILDER_VERSION,
        },
        containers::{
            BeaconState, SignedBeaconBlock,
            gloas::{
                BeaconBlock, Builder, ExecutionPayloadBid, ExecutionRequests, ProposerPreferences,
                SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope,
                SignedProposerPreferences,
            },
        },
        primitives::{BlsPubkey, BlsSignature, ExecutionAddress, HashTreeRoot as _},
        signing::compute_epoch_at_slot,
    },
    primitives::H256,
};
use http_body_util::BodyExt as _;
use libssz::{SszDecode as _, SszEncode as _};
use tower::ServiceExt as _;

use super::{Prepared, prepare, routes as produce_routes};
use crate::beacon::graffiti::OwnVersion;
use crate::{
    CustodyColumns,
    beacon::{bids, proposer_preferences, validator::FeeRecipients},
    test_utils::{RecordingNetwork, beacon_store_with_head_block, gloas_beacon_block},
};

/// The slot the block is built for. The head block sits one slot earlier, and
/// the clock is at the head's slot, so this one is the next slot: the one bids
/// and preferences are accepted for.
const SLOT: u64 = 33;
const HEAD_SLOT: u64 = SLOT - 1;
const GWEI: u64 = 1_000_000_000;

// ---------------------------------------------------------------------------
// Fake execution client
// ---------------------------------------------------------------------------

/// A stand-in execution client and what it was asked to build.
struct FakeEngine {
    client: EngineClient,
    /// The payload attributes the last `forkchoiceUpdatedV4` carried.
    attributes: Arc<Mutex<Option<serde_json::Value>>>,
}

/// `forkchoiceUpdated` with attributes answers a payload id, and `getPayloadV6`
/// a payload extending the requested head with exactly the requested
/// attributes, worth `block_value_wei`.
async fn fake_engine(block_value_wei: u64, should_override_builder: bool) -> FakeEngine {
    use axum::{Json, routing::post};

    let attributes: Arc<Mutex<Option<serde_json::Value>>> = Arc::default();
    let recorded = attributes.clone();
    let handler = move |Json(request): Json<serde_json::Value>| {
        let recorded = recorded.clone();
        async move {
            let result = match request["method"].as_str() {
                Some("engine_forkchoiceUpdatedV4") => {
                    let mut attributes = request["params"][1].clone();
                    attributes["parentHash"] = request["params"][0]["headBlockHash"].clone();
                    *recorded.lock().unwrap() = Some(attributes);
                    serde_json::json!({
                        "payloadStatus": { "status": "VALID", "latestValidHash": null },
                        "payloadId": "0x0000000000000001",
                    })
                }
                Some("engine_getPayloadV6") => {
                    let attributes = recorded.lock().unwrap().clone().unwrap();
                    serde_json::json!({
                        "executionPayload": {
                            "parentHash": attributes["parentHash"],
                            "feeRecipient": attributes["suggestedFeeRecipient"],
                            "stateRoot": format!("0x{}", "00".repeat(32)),
                            "receiptsRoot": format!("0x{}", "00".repeat(32)),
                            "logsBloom": format!("0x{}", "00".repeat(256)),
                            "prevRandao": attributes["prevRandao"],
                            "blockNumber": "0x1",
                            "gasLimit": attributes["targetGasLimit"],
                            "gasUsed": "0x0",
                            "timestamp": attributes["timestamp"],
                            "extraData": "0x",
                            "baseFeePerGas": "0x7",
                            "blockHash": format!("0x{}", "ee".repeat(32)),
                            "transactions": [],
                            "withdrawals": attributes["withdrawals"],
                            "blobGasUsed": "0x0",
                            "excessBlobGas": "0x0",
                            "blockAccessList": "0xc0",
                            "slotNumber": attributes["slotNumber"],
                        },
                        "blockValue": format!("0x{block_value_wei:x}"),
                        "blobsBundle": { "commitments": [], "proofs": [], "blobs": [] },
                        "shouldOverrideBuilder": should_override_builder,
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
    let router = Router::new().route("/", post(handler));
    tokio::spawn(async move { axum::serve(listener, router).await });
    FakeEngine {
        client: EngineClient::new(format!("http://{address}"), JwtSecret::new([0x0f; 32])).unwrap(),
        attributes,
    }
}

/// An execution client nothing listens for, so every build fails.
fn dead_engine() -> FakeEngine {
    FakeEngine {
        client: EngineClient::new("http://127.0.0.1:1".to_string(), JwtSecret::new([0x0f; 32]))
            .unwrap(),
        attributes: Arc::default(),
    }
}

impl FakeEngine {
    fn requested(&self) -> serde_json::Value {
        self.attributes
            .lock()
            .unwrap()
            .clone()
            .expect("the engine was asked to build")
    }
}

// ---------------------------------------------------------------------------
// The chain
// ---------------------------------------------------------------------------

fn builder_pubkey() -> BlsPubkey {
    BlsPubkey(secret_key_for(1000).sk_to_pk().to_bytes())
}

fn sign_as_builder(root: H256) -> BlsSignature {
    BlsSignature(
        secret_key_for(1000)
            .sign(
                root.as_slice(),
                ethlambda_state_transition::beacon::bls::DST,
                &[],
            )
            .to_bytes(),
    )
}

/// The block at slot 0 whose root the head state names as the dependent root of
/// every slot of the first two epochs.
fn genesis_block() -> SignedBeaconBlock {
    gloas_beacon_block(0, H256::ZERO, H256::ZERO, H256::repeat_byte(0x0a))
}

/// A gloas head state at slot 32 whose registry holds one funded, active
/// builder (index 0, key `secret_key_for(1000)`) and whose block roots name the
/// genesis block.
fn chain_state() -> BeaconState {
    let mut state = parent_state();
    let genesis_root = genesis_block().message_hash_tree_root();
    let BeaconState::Gloas(inner) = &mut state else {
        unreachable!("built as gloas")
    };
    // `is_active_builder` wants the deposit epoch below the finalized one.
    inner.finalized_checkpoint.epoch = 1;
    inner.builders.push(Builder {
        pubkey: builder_pubkey(),
        version: PAYLOAD_BUILDER_VERSION,
        execution_address: ExecutionAddress::ZERO,
        balance: 100_000_000_000,
        deposit_epoch: 0,
        withdrawable_epoch: FAR_FUTURE_EPOCH,
    });
    inner.block_roots[0] = genesis_root;
    state
}

struct World {
    store: Store,
    state: BeaconState,
    head_root: H256,
    market: SharedBuilderMarket,
    network: Arc<RecordingNetwork>,
    fee_recipients: FeeRecipients,
}

impl World {
    /// The head block at slot 32 on a clock where that slot is running.
    fn new() -> Self {
        let state = chain_state();
        let genesis = genesis_block();
        let genesis_root = genesis.message_hash_tree_root();
        let block = gloas_beacon_block(
            state.slot(),
            genesis_root,
            H256::repeat_byte(0x01),
            H256::repeat_byte(0x02),
        );
        // The root a block built on this state names as its parent.
        let mut header = state.latest_block_header().clone();
        header.state_root = state.hash_tree_root();
        let head_root = header.hash_tree_root();
        let mut store = beacon_store_with_head_block(
            state.clone(),
            chain_config(),
            block,
            head_root,
            HEAD_SLOT,
        );
        store.insert_signed_block(genesis_root, genesis).unwrap();
        store.insert_state(genesis_root, state.clone()).unwrap();
        Self {
            store,
            state,
            head_root,
            market: SharedBuilderMarket::default(),
            network: Arc::default(),
            fee_recipients: FeeRecipients::default(),
        }
    }

    fn app(&self, engine: Option<&FakeEngine>) -> Router {
        let p2p: RpcToP2PRef = self.network.clone();
        produce_routes()
            .merge(bids::routes())
            .merge(proposer_preferences::routes())
            .with_state(self.store.clone())
            .layer(Extension(p2p))
            .layer(Extension(engine.map(|engine| engine.client.clone())))
            .layer(Extension(SharedSyncCommitteePool::default()))
            .layer(Extension(SharedPayloadAttestationPool::default()))
            .layer(Extension(self.market.clone()))
            .layer(Extension(self.fee_recipients.clone()))
            .layer(Extension(CustodyColumns::default()))
            .layer(Extension(OwnVersion(Arc::new(
                ethlambda_engine::types::ClientVersionV1 {
                    code: "LA".to_string(),
                    name: "ethlambda".to_string(),
                    version: "ethlambda/test".to_string(),
                    commit: "0x3c4d7e8f".to_string(),
                },
            ))))
    }

    fn advanced(&self) -> BeaconState {
        advance_to_slot(&self.state, SLOT, &chain_config()).unwrap()
    }

    /// What `produceBlockV4` reads off the chain for [`SLOT`].
    fn prepared(&self) -> Prepared {
        prepare(
            &self.store,
            &self.market,
            SLOT,
            randao_reveal(&self.advanced()),
        )
        .unwrap()
    }

    /// A bid of builder 0 on the parent payload `produceBlockV4` builds on,
    /// signed under the builder domain.
    fn bid(&self, value: u64, fee_recipient: ExecutionAddress) -> SignedExecutionPayloadBid {
        let prepared = self.prepared();
        let message = ExecutionPayloadBid {
            parent_block_hash: prepared.inputs.head_block_hash,
            parent_block_root: prepared.head_root,
            block_hash: H256::repeat_byte(0xb1),
            prev_randao: prepared.inputs.prev_randao,
            fee_recipient,
            gas_limit: prepared.inputs.target_gas_limit,
            builder_index: 0,
            slot: SLOT,
            value,
            execution_payment: 0,
            blob_kzg_commitments: Default::default(),
            execution_requests_root: ExecutionRequests::default().hash_tree_root(),
        };
        let domain = get_domain(&prepared.state, DOMAIN_BEACON_BUILDER, None);
        let signing_root = compute_signing_root(message.hash_tree_root(), domain);
        SignedExecutionPayloadBid {
            message,
            signature: sign_as_builder(signing_root),
        }
    }

    /// The proposer's preferences for [`SLOT`], signed with its key.
    fn preferences(&self, fee_recipient: ExecutionAddress, gas: u64) -> SignedProposerPreferences {
        self.preferences_by(self.prepared().proposer, fee_recipient, gas)
    }

    /// Preferences naming `validator`, signed with that validator's key.
    fn preferences_by(
        &self,
        validator: u64,
        fee_recipient: ExecutionAddress,
        gas: u64,
    ) -> SignedProposerPreferences {
        let dependent_root = dependent_root_at(&self.state, self.head_root, SLOT)
            .expect("the head's chain gives the slot a dependent root");
        let message = ProposerPreferences {
            dependent_root,
            proposal_slot: SLOT,
            validator_index: validator,
            fee_recipient,
            target_gas_limit: gas,
        };
        let domain = proposer_preferences_domain(
            &chain_config(),
            self.state.genesis_validators_root(),
            compute_epoch_at_slot(SLOT),
        );
        let signing_root = compute_signing_root(message.hash_tree_root(), domain);
        SignedProposerPreferences {
            signature: sign_for(validator as usize, signing_root),
            message,
        }
    }

    /// Preferences recorded straight into the market, without the gossip rules.
    fn prime_preferences(&self, fee_recipient: ExecutionAddress, gas: u64) {
        let signed = self.preferences(fee_recipient, gas);
        assert!(self.market.record_preferences(signed, HEAD_SLOT));
    }

    fn prime_bid(&self, bid: &SignedExecutionPayloadBid) {
        assert!(self.market.record_bid(bid.clone()));
    }

    /// The parent payload bids are judged against becomes known to gossip, as
    /// its envelope arriving would make it.
    fn reveal_parent_payload(&self) {
        let prepared = self.prepared();
        let mut envelope = crate::test_utils::gloas_envelope(self.head_root, HEAD_SLOT);
        envelope.message.payload.block_hash = prepared.inputs.head_block_hash;
        envelope.message.payload.gas_limit = 30_000_000;
        self.market.record_execution_payload(&envelope.message);
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or_default()
    }
}

async fn send(app: &Router, request: Request<Body>) -> Reply {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    Reply {
        status,
        headers,
        body,
    }
}

fn address(byte: u8) -> ExecutionAddress {
    ExecutionAddress::repeat_byte(byte)
}

// ---------------------------------------------------------------------------
// produceBlockV4
// ---------------------------------------------------------------------------

fn builder_config(min_bid: u64, factor: u64) -> String {
    format!(r#"{{"min_bid":"{min_bid}","builder_boost_factor":"{factor}","builders":[]}}"#)
}

fn produce_request(
    world: &World,
    include_payload: bool,
    config: &str,
    accept_ssz: bool,
) -> Request<Body> {
    let reveal = randao_reveal(&world.advanced());
    let mut request = Request::post(format!(
        "/eth/v4/validator/blocks/{SLOT}?randao_reveal=0x{}&include_payload={include_payload}",
        hex::encode(reveal.0)
    ))
    .header("eth-consensus-version", "gloas")
    .header("content-type", "application/json");
    if accept_ssz {
        request = request.header("accept", "application/octet-stream");
    }
    request.body(Body::from(config.to_string())).unwrap()
}

async fn produce(
    world: &World,
    engine: Option<&FakeEngine>,
    include_payload: bool,
    config: &str,
) -> Reply {
    send(
        &world.app(engine),
        produce_request(world, include_payload, config, false),
    )
    .await
}

/// The bid the produced block commits to, from a JSON response either way: a
/// bare block, or contents carrying it.
fn produced_block_bid(reply: &Reply) -> ExecutionPayloadBid {
    let data = &reply.json()["data"];
    let block = if data.get("block").is_some() {
        &data["block"]
    } else {
        data
    };
    serde_json::from_value(block["body"]["signed_execution_payload_bid"]["message"].clone())
        .expect("a gloas block carries its bid")
}

fn self_built(reply: &Reply) -> bool {
    produced_block_bid(reply).builder_index == BUILDER_INDEX_SELF_BUILD
}

#[tokio::test]
async fn a_bid_worth_more_than_the_local_payload_is_built_on_and_returned_bare() {
    let world = World::new();
    let engine = fake_engine(GWEI, false).await;
    let bid = world.bid(5, address(0xcc));
    world.prime_bid(&bid);

    // Factor 100 weights both sides evenly: 5 gwei against 1 gwei.
    let reply = produce(&world, Some(&engine), true, &builder_config(0, 100)).await;

    assert_eq!(
        reply.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    assert_eq!(produced_block_bid(&reply), bid.message);
    // `include_payload=true` still comes back bare: the builder reveals.
    let json = reply.json();
    assert_eq!(json["execution_payload_included"], false);
    assert_eq!(json["version"], "gloas");
    assert!(json["data"].get("execution_payload_envelope").is_none());
    assert_eq!(reply.headers["eth-execution-payload-included"], "false");
    assert_eq!(
        reply.headers["eth-execution-payload-value"],
        (5 * GWEI).to_string().as_str()
    );
    assert_eq!(reply.headers["eth-consensus-block-value"], "0");
    assert_eq!(reply.headers["eth-consensus-version"], "gloas");
    assert!(reply.headers.get("eth-builder-url").is_none());
}

#[tokio::test]
async fn a_bid_won_block_is_served_as_ssz_too() {
    let world = World::new();
    let engine = fake_engine(GWEI, false).await;
    let bid = world.bid(5, address(0xcc));
    world.prime_bid(&bid);

    let reply = send(
        &world.app(Some(&engine)),
        produce_request(&world, false, &builder_config(0, 100), true),
    )
    .await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.headers["eth-execution-payload-included"], "false");
    let block = BeaconBlock::from_ssz_bytes(&reply.body).unwrap();
    assert_eq!(block.body.signed_execution_payload_bid, bid);
}

#[tokio::test]
async fn nothing_is_cached_for_a_bid_block_and_a_self_build_envelope_for_it_is_refused() {
    let world = World::new();
    let engine = fake_engine(GWEI, false).await;
    world.prime_bid(&world.bid(5, address(0xcc)));
    let app = world.app(Some(&engine));
    let reply = send(
        &app,
        produce_request(&world, false, &builder_config(0, 100), true),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let block = BeaconBlock::from_ssz_bytes(&reply.body).unwrap();
    let root = block.hash_tree_root();

    // No envelope was cached for the block.
    let reply = send(
        &app,
        Request::get(format!(
            "/eth/v1/validator/execution_payload_envelopes/{SLOT}/{root:?}"
        ))
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);

    // The block is imported; the proposer's self-build envelope for it names
    // a different builder than the bid, so it is refused.
    let mut store = world.store.clone();
    let post = post_state(&world.advanced(), &block);
    store
        .insert_signed_block(
            root,
            SignedBeaconBlock::Gloas(
                ethlambda_types::beacon::containers::gloas::SignedBeaconBlock {
                    message: block,
                    signature: Default::default(),
                },
            ),
        )
        .unwrap();
    store.insert_state(root, post).unwrap();
    let mut envelope = crate::test_utils::gloas_envelope(root, SLOT);
    envelope.message.builder_index = BUILDER_INDEX_SELF_BUILD;
    let request = Request::post("/eth/v1/beacon/execution_payload_envelopes")
        .header("eth-consensus-version", "gloas")
        .header("eth-blob-data-included", "false")
        .header("content-type", crate::SSZ_CONTENT_TYPE)
        .body(Body::from(SignedExecutionPayloadEnvelope::to_ssz(
            &envelope,
        )))
        .unwrap();
    let reply = send(&app, request).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        reply.json()["message"],
        "the envelope does not fulfill the block's bid"
    );
    assert!(world.network.envelopes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn the_local_payload_wins_ties_a_zero_factor_a_floor_and_an_override() {
    // (local value in wei, should_override, min_bid in gwei, factor)
    let cases = [
        // 5 gwei each side at factor 100: a tie.
        (5 * GWEI, false, 0, 100),
        // Factor 0 prefers the local payload.
        (1, false, 0, 0),
        // The bid is below the config's floor.
        (1, false, 6, u64::MAX),
        // The engine insists on its own payload.
        (1, true, 0, u64::MAX),
    ];
    for (local_wei, should_override, min_bid, factor) in cases {
        let world = World::new();
        let engine = fake_engine(local_wei, should_override).await;
        world.prime_bid(&world.bid(5, address(0xcc)));

        let reply = produce(
            &world,
            Some(&engine),
            true,
            &builder_config(min_bid, factor),
        )
        .await;

        assert_eq!(
            reply.status,
            StatusCode::OK,
            "{local_wei} {min_bid} {factor}"
        );
        assert!(
            self_built(&reply),
            "{local_wei} {should_override} {min_bid} {factor}"
        );
        assert_eq!(reply.json()["execution_payload_included"], true);
        assert_eq!(reply.headers["eth-execution-payload-included"], "true");
        assert!(
            reply.json()["data"]
                .get("execution_payload_envelope")
                .is_some()
        );
    }
}

#[tokio::test]
async fn a_bid_wins_when_the_local_build_is_below_it_by_one_unit_of_weight() {
    // 1e9 wei is 1 gwei: a tie at factor 100. One wei less and the bid wins.
    for (local_wei, bid_wins) in [(GWEI, false), (GWEI - 1, true)] {
        let world = World::new();
        let engine = fake_engine(local_wei, false).await;
        world.prime_bid(&world.bid(1, address(0xcc)));

        let reply = produce(&world, Some(&engine), false, &builder_config(0, 100)).await;

        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(self_built(&reply), !bid_wins, "{local_wei}");
    }
}

#[tokio::test]
async fn without_an_engine_a_viable_bid_is_built_on_and_none_is_a_503() {
    let world = World::new();
    let reply = produce(&world, None, true, &builder_config(0, 0)).await;
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);

    let bid = world.bid(5, address(0xcc));
    world.prime_bid(&bid);
    // Even a factor of 0 takes the bid when there is nothing to prefer.
    let reply = produce(&world, None, true, &builder_config(0, 0)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(produced_block_bid(&reply), bid.message);

    // A bid under the floor is not viable.
    let reply = produce(&world, None, true, &builder_config(6, 100)).await;
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn a_failed_local_build_falls_back_to_a_viable_bid() {
    let world = World::new();
    let engine = dead_engine();
    let reply = produce(&world, Some(&engine), true, &builder_config(0, 0)).await;
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);

    let bid = world.bid(5, address(0xcc));
    world.prime_bid(&bid);
    let reply = produce(&world, Some(&engine), true, &builder_config(0, 0)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(produced_block_bid(&reply), bid.message);
}

#[tokio::test]
async fn bids_that_do_not_fit_the_slot_are_left_to_the_local_payload() {
    // Each would win on value (factor MAX against a 1 wei local build).
    type Change = fn(&mut ExecutionPayloadBid);
    let mismatches: [(&str, Change); 3] = [
        ("randao", |bid| bid.prev_randao = H256::repeat_byte(0x99)),
        ("parent hash", |bid| {
            bid.parent_block_hash = H256::repeat_byte(0x98)
        }),
        ("parent root", |bid| {
            bid.parent_block_root = H256::repeat_byte(0x97)
        }),
    ];
    for (name, change) in mismatches {
        let world = World::new();
        let engine = fake_engine(1, false).await;
        let mut bid = world.bid(5, address(0xcc));
        change(&mut bid.message);
        // Re-signing is beside the point: the pool is keyed on the fields that
        // changed, and a bid that does not match never reaches a block.
        world.market.record_bid(bid);

        let reply = produce(&world, Some(&engine), true, &builder_config(0, u64::MAX)).await;

        assert_eq!(reply.status, StatusCode::OK, "{name}");
        assert!(self_built(&reply), "{name}");
    }
}

#[tokio::test]
async fn a_bid_paying_someone_other_than_the_preferred_recipient_is_skipped() {
    let world = World::new();
    let engine = fake_engine(1, false).await;
    world.prime_preferences(address(0xaa), 30_000_000);
    world.prime_bid(&world.bid(5, address(0xcc)));

    let reply = produce(&world, Some(&engine), true, &builder_config(0, u64::MAX)).await;

    assert_eq!(reply.status, StatusCode::OK);
    assert!(self_built(&reply));
}

#[tokio::test]
async fn a_bid_paying_the_preferred_recipient_is_taken() {
    let world = World::new();
    let engine = fake_engine(1, false).await;
    world.prime_preferences(address(0xaa), 30_000_000);
    let bid = world.bid(5, address(0xaa));
    world.prime_bid(&bid);

    let reply = produce(&world, Some(&engine), true, &builder_config(0, u64::MAX)).await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(produced_block_bid(&reply), bid.message);
}

#[tokio::test]
async fn the_self_build_takes_its_fee_recipient_and_gas_target_from_the_preferences() {
    let world = World::new();
    let engine = fake_engine(GWEI, false).await;
    let proposer = world.prepared().proposer;
    world
        .fee_recipients
        .lock()
        .unwrap()
        .insert(proposer, address(0xbb));
    world.prime_preferences(address(0xaa), 31_000_000);

    let reply = produce(&world, Some(&engine), true, &builder_config(0, 0)).await;

    assert_eq!(reply.status, StatusCode::OK);
    let requested = engine.requested();
    assert_eq!(
        requested["suggestedFeeRecipient"],
        format!("0x{}", "aa".repeat(20))
    );
    assert_eq!(
        requested["targetGasLimit"],
        format!("0x{:x}", 31_000_000u64)
    );
    // The payload the engine built carries them into the block's bid.
    let bid = produced_block_bid(&reply);
    assert_eq!(bid.fee_recipient, address(0xaa));
    assert_eq!(bid.gas_limit, 31_000_000);
}

#[tokio::test]
async fn without_preferences_the_self_build_falls_back_to_the_prepared_recipient_and_parent_gas() {
    let world = World::new();
    let engine = fake_engine(GWEI, false).await;
    let proposer = world.prepared().proposer;
    world
        .fee_recipients
        .lock()
        .unwrap()
        .insert(proposer, address(0xbb));

    let reply = produce(&world, Some(&engine), true, &builder_config(0, 0)).await;

    assert_eq!(reply.status, StatusCode::OK);
    let requested = engine.requested();
    assert_eq!(
        requested["suggestedFeeRecipient"],
        format!("0x{}", "bb".repeat(20))
    );
    // The parent bid's gas limit, which is what `chain_state` gives it.
    assert_eq!(
        requested["targetGasLimit"],
        format!("0x{:x}", 30_000_000u64)
    );

    // Neither: the zero address.
    let world = World::new();
    let engine = fake_engine(GWEI, false).await;
    produce(&world, Some(&engine), true, &builder_config(0, 0)).await;
    assert_eq!(
        engine.requested()["suggestedFeeRecipient"],
        format!("0x{}", "00".repeat(20))
    );
}

#[tokio::test]
async fn preferences_of_another_validator_are_not_the_proposers() {
    let world = World::new();
    let engine = fake_engine(GWEI, false).await;
    let proposer = world.prepared().proposer;
    let other = (proposer + 1) % 64;
    let stranger = world.preferences_by(other, address(0xaa), 31_000_000);
    assert!(world.market.record_preferences(stranger, HEAD_SLOT));

    produce(&world, Some(&engine), true, &builder_config(0, 0)).await;

    let requested = engine.requested();
    assert_eq!(
        requested["suggestedFeeRecipient"],
        format!("0x{}", "00".repeat(20))
    );
    assert_eq!(
        requested["targetGasLimit"],
        format!("0x{:x}", 30_000_000u64)
    );
}

#[tokio::test]
async fn the_existing_error_paths_are_unchanged() {
    let world = World::new();
    let app = world.app(None);
    // A pre-existing client sends the empty local-preferred config.
    let reply = send(
        &app,
        produce_request(&world, true, &builder_config(0, 0), false),
    )
    .await;
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
    let reply = send(&app, produce_request(&world, true, "not a config", false)).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()["message"], "the body is not a BuilderConfig");
}

// ---------------------------------------------------------------------------
// POST execution_payload_bids
// ---------------------------------------------------------------------------

fn bid_request(bid: &SignedExecutionPayloadBid) -> Request<Body> {
    Request::post("/eth/v1/beacon/execution_payload_bids")
        .header("eth-consensus-version", "gloas")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(bid).unwrap()))
        .unwrap()
}

/// A world where a bid of builder 0 passes every rule: the preferences for the
/// slot are cached and the parent payload is known.
fn world_ready_for_bids() -> World {
    let world = World::new();
    world.prime_preferences(address(0xaa), 30_000_000);
    world.reveal_parent_payload();
    world
}

#[tokio::test]
async fn a_valid_bid_is_pooled_and_published_once() {
    let world = world_ready_for_bids();
    let app = world.app(None);
    let bid = world.bid(5, address(0xaa));

    let reply = send(&app, bid_request(&bid)).await;

    assert_eq!(
        reply.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    assert_eq!(*world.network.bids.lock().unwrap(), vec![bid.clone()]);
    assert!(world.market.contains_bid(&bid));

    // An identical resubmission is a success and is not gossiped again.
    let reply = send(&app, bid_request(&bid)).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(world.network.bids.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_pooled_bid_resubmitted_is_a_200_without_a_publish() {
    // Needs only the market: the identical bid short-circuits the rules.
    let world = World::new();
    let bid = world.bid(5, address(0xaa));
    world.prime_bid(&bid);

    let reply = send(&world.app(None), bid_request(&bid)).await;

    assert_eq!(reply.status, StatusCode::OK);
    assert!(world.network.bids.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_bid_is_accepted_as_ssz() {
    let world = world_ready_for_bids();
    let bid = world.bid(5, address(0xaa));
    let request = Request::post("/eth/v1/beacon/execution_payload_bids")
        .header("eth-consensus-version", "gloas")
        .header("content-type", crate::SSZ_CONTENT_TYPE)
        .body(Body::from(bid.to_ssz()))
        .unwrap();

    let reply = send(&world.app(None), request).await;

    assert_eq!(
        reply.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    assert_eq!(*world.network.bids.lock().unwrap(), vec![bid]);
}

#[tokio::test]
async fn a_bid_with_a_bad_signature_is_a_400_naming_the_verdict() {
    let world = world_ready_for_bids();
    let mut bid = world.bid(5, address(0xaa));
    bid.signature = BlsSignature::default();

    let reply = send(&world.app(None), bid_request(&bid)).await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()["code"], 400);
    assert_eq!(reply.json()["message"], "reject: bad_signature");
    assert!(world.network.bids.lock().unwrap().is_empty());
    assert!(!world.market.contains_bid(&bid));
}

#[tokio::test]
async fn a_bid_for_a_slot_without_preferences_is_a_400() {
    let world = World::new();
    world.reveal_parent_payload();
    let bid = world.bid(5, address(0xaa));

    let reply = send(&world.app(None), bid_request(&bid)).await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json()["message"], "ignore: preferences_unseen");
    assert!(world.network.bids.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_lower_bid_after_a_higher_one_is_refused_and_the_verdict_is_a_400() {
    let world = world_ready_for_bids();
    let app = world.app(None);
    let high = world.bid(9, address(0xaa));
    assert_eq!(send(&app, bid_request(&high)).await.status, StatusCode::OK);
    let mut low = world.bid(5, address(0xaa));
    low.message.builder_index = 0;

    let reply = send(&app, bid_request(&low)).await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(world.network.bids.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_bid_with_a_wrong_header_or_content_type_or_body_is_refused() {
    let world = world_ready_for_bids();
    let app = world.app(None);
    let bid = world.bid(5, address(0xaa));
    let json = serde_json::to_vec(&bid).unwrap();

    let wrong_fork = Request::post("/eth/v1/beacon/execution_payload_bids")
        .header("eth-consensus-version", "fulu")
        .body(Body::from(json.clone()))
        .unwrap();
    assert_eq!(send(&app, wrong_fork).await.status, StatusCode::BAD_REQUEST);

    let plain = Request::post("/eth/v1/beacon/execution_payload_bids")
        .header("content-type", "text/plain")
        .body(Body::from(json.clone()))
        .unwrap();
    assert_eq!(
        send(&app, plain).await.status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );

    let garbage = Request::post("/eth/v1/beacon/execution_payload_bids")
        .body(Body::from("not a bid"))
        .unwrap();
    assert_eq!(send(&app, garbage).await.status, StatusCode::BAD_REQUEST);

    let oversized = Request::post("/eth/v1/beacon/execution_payload_bids")
        .header("content-type", crate::SSZ_CONTENT_TYPE)
        .body(Body::from(vec![0u8; 196_933]))
        .unwrap();
    assert_eq!(send(&app, oversized).await.status, StatusCode::BAD_REQUEST);

    // No header at all is read leniently.
    let lenient = Request::post("/eth/v1/beacon/execution_payload_bids")
        .body(Body::from(json))
        .unwrap();
    assert_eq!(send(&app, lenient).await.status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// POST proposer_preferences
// ---------------------------------------------------------------------------

fn preferences_request(
    preferences: &[SignedProposerPreferences],
    version: Option<&str>,
) -> Request<Body> {
    let mut request = Request::post("/eth/v1/validator/proposer_preferences")
        .header("content-type", "application/json");
    if let Some(version) = version {
        request = request.header("eth-consensus-version", version);
    }
    request
        .body(Body::from(serde_json::to_vec(preferences).unwrap()))
        .unwrap()
}

#[tokio::test]
async fn valid_preferences_are_cached_and_published_once() {
    let world = World::new();
    let app = world.app(None);
    let signed = world.preferences(address(0xaa), 30_000_000);

    let reply = send(
        &app,
        preferences_request(std::slice::from_ref(&signed), Some("gloas")),
    )
    .await;

    assert_eq!(
        reply.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    assert_eq!(
        *world.network.proposer_preferences.lock().unwrap(),
        vec![signed.clone()]
    );
    assert_eq!(
        world
            .market
            .preferences(SLOT, signed.message.dependent_root),
        Some(signed.clone())
    );

    // The same again is a success without a second publish.
    let reply = send(&app, preferences_request(&[signed], Some("gloas"))).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(world.network.proposer_preferences.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn cached_preferences_resubmitted_are_a_200_without_a_publish() {
    // Needs only the market: an identical entry short-circuits the rules.
    let world = World::new();
    let signed = world.preferences(address(0xaa), 30_000_000);
    assert!(world.market.record_preferences(signed.clone(), HEAD_SLOT));

    let reply = send(&world.app(None), preferences_request(&[signed], None)).await;

    assert_eq!(reply.status, StatusCode::OK);
    assert!(
        world
            .network
            .proposer_preferences
            .lock()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn different_preferences_for_a_held_key_fail_with_their_position() {
    let world = World::new();
    let first = world.preferences(address(0xaa), 30_000_000);
    let second = world.preferences(address(0xbb), 30_000_000);

    let reply = send(
        &world.app(None),
        preferences_request(&[first.clone(), second], Some("gloas")),
    )
    .await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let json = reply.json();
    assert_eq!(json["code"], 400);
    assert_eq!(json["failures"].as_array().unwrap().len(), 1);
    assert_eq!(json["failures"][0]["index"], 1);
    assert_eq!(json["failures"][0]["message"], "ignore: already_seen");
    // The first still went out.
    assert_eq!(
        *world.network.proposer_preferences.lock().unwrap(),
        vec![first]
    );
}

#[tokio::test]
async fn preferences_by_the_wrong_proposer_or_signer_fail_and_the_rest_still_go_out() {
    let world = World::new();
    let proposer = world.prepared().proposer;
    let wrong_proposer = world.preferences_by((proposer + 1) % 64, address(0xaa), 30_000_000);
    let mut bad_signature = world.preferences(address(0xaa), 30_000_000);
    bad_signature.signature = BlsSignature::default();
    let good = world.preferences(address(0xcc), 30_000_000);

    let reply = send(
        &world.app(None),
        preferences_request(
            &[wrong_proposer, bad_signature, good.clone()],
            Some("gloas"),
        ),
    )
    .await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let json = reply.json();
    let failures: Vec<(u64, String)> = json["failures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|failure| {
            (
                failure["index"].as_u64().unwrap(),
                failure["message"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        failures,
        vec![
            (0, "reject: wrong_proposer".to_string()),
            (1, "reject: bad_signature".to_string()),
        ]
    );
    assert_eq!(
        *world.network.proposer_preferences.lock().unwrap(),
        vec![good]
    );
}

#[tokio::test]
async fn preferences_are_accepted_as_an_ssz_list_and_the_header_may_be_fulu() {
    let world = World::new();
    let signed = world.preferences(address(0xaa), 30_000_000);
    let request = Request::post("/eth/v1/validator/proposer_preferences")
        .header("content-type", crate::SSZ_CONTENT_TYPE)
        .header("eth-consensus-version", "fulu")
        .body(Body::from(vec![signed.clone()].to_ssz()))
        .unwrap();

    let reply = send(&world.app(None), request).await;

    assert_eq!(
        reply.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    assert_eq!(
        *world.network.proposer_preferences.lock().unwrap(),
        vec![signed]
    );
}

#[tokio::test]
async fn preferences_with_a_bad_header_type_body_or_count_are_refused() {
    let world = World::new();
    let app = world.app(None);
    let signed = world.preferences(address(0xaa), 30_000_000);

    for version in ["electra", "nonsense"] {
        let reply = send(
            &app,
            preferences_request(std::slice::from_ref(&signed), Some(version)),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{version}");
    }
    let plain = Request::post("/eth/v1/validator/proposer_preferences")
        .header("content-type", "text/plain")
        .body(Body::from("[]"))
        .unwrap();
    assert_eq!(
        send(&app, plain).await.status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    let garbage = Request::post("/eth/v1/validator/proposer_preferences")
        .body(Body::from("not json"))
        .unwrap();
    assert_eq!(send(&app, garbage).await.status, StatusCode::BAD_REQUEST);

    // One over the list bound is refused before any entry is looked at.
    let many =
        vec![signed; ethlambda_state_transition::beacon::preset::PROPOSER_LOOKAHEAD_LENGTH + 1];
    let reply = send(&app, preferences_request(&many, Some("gloas"))).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(
        world
            .network
            .proposer_preferences
            .lock()
            .unwrap()
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// Every new route answers something other than a 500 through the layer set
/// the production server applies, and the phase-2 route does not exist.
#[tokio::test]
async fn the_new_routes_are_wired_with_the_production_layers() {
    use ethlambda_blockchain::{SyncStatusController, metrics::SyncStatus};

    let world = World::new();
    let router =
        crate::build_beacon_api_router(world.store.clone(), "ethlambda/test", "peer".into())
            .layer(Extension(SyncStatusController::new(SyncStatus::Synced)))
            .layer(Extension::<RpcToP2PRef>(world.network.clone()))
            .layer(Extension(SharedSyncCommitteePool::default()))
            .layer(Extension(SharedPayloadAttestationPool::default()))
            .layer(Extension(world.market.clone()))
            .layer(Extension(CustodyColumns::default()))
            .layer(Extension(FeeRecipients::default()))
            .layer(Extension(None::<EngineClient>));

    for (uri, body) in [
        ("/eth/v1/beacon/execution_payload_bids", "{}"),
        ("/eth/v1/validator/proposer_preferences", "[]"),
        ("/eth/v1/beacon/states/head/builders", ""),
    ] {
        let reply = send(&router, Request::post(uri).body(Body::from(body)).unwrap()).await;
        assert_ne!(reply.status, StatusCode::INTERNAL_SERVER_ERROR, "{uri}");
        assert_ne!(reply.status, StatusCode::NOT_FOUND, "{uri}");
    }
    let reply = send(
        &router,
        Request::post("/eth/v1/validator/builder_preferences")
            .body(Body::from("[]"))
            .unwrap(),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}
