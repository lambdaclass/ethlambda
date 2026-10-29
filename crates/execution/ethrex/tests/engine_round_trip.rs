//! The in-process Engine API against a real embedded ethrex.
//!
//! Each test starts a node on an in-memory database with devp2p off, from a
//! checked-in dev genesis whose every fork is active at genesis, and drives it
//! through `EngineClient::in_process` the way a proposer and then a follower
//! would: ask ethrex to build a payload, take it, and hand it back for import.
//! ethrex rebuilds the block from what it is given and checks the block hash
//! the payload claims, so a payload that survives the trip proves the typed
//! conversion field for field.
//!
//! The genesis files are ethrex's own dev genesis (`fixtures/genesis/l1.json`
//! and `l1-bal.json` at the pinned tag) cut down to the accounts that carry
//! code: the system contracts a Prague block calls. Full sync, since a snap
//! node answers every forkchoice update `SYNCING` until its first sync ends.

use std::path::{Path, PathBuf};

use clap::Parser;
use ethlambda_engine::building::{PayloadAttributesV3, PayloadAttributesV4};
use ethlambda_engine::{
    ETHLAMBDA_ENGINE_CAPABILITIES, EngineClient, EngineError, ForkchoiceStateV1, PayloadStatusValue,
};
use ethlambda_ethrex::{EmbeddedEthrex, EthrexArgs};
use ethlambda_types::beacon::containers::bellatrix;
use ethlambda_types::beacon::primitives::{H160, H256};
use ethrex_config::networks::Network;

#[derive(Parser)]
struct Harness {
    #[command(flatten)]
    ethrex: EthrexArgs,
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// The genesis block's hash and timestamp, as ethrex computes them.
fn genesis(name: &str) -> (H256, u64) {
    let genesis = Network::GenesisPath(fixture(name))
        .get_genesis()
        .expect("the fixture is a valid genesis");
    (H256(genesis.get_block().hash().0), genesis.timestamp)
}

async fn embedded(genesis: &str, extra_flags: &[&str]) -> EmbeddedEthrex {
    let network = fixture(genesis);
    let network = network.to_str().expect("a UTF-8 fixture path");
    let mut argv = vec![
        "ethlambda",
        "--ethrex.datadir",
        "memory",
        "--ethrex.network",
        network,
        "--ethrex.syncmode",
        "full",
    ];
    argv.extend_from_slice(extra_flags);
    let args = Harness::try_parse_from(argv).expect("valid flags").ethrex;
    // The beacon values only fill gaps the flags above leave, and they leave
    // none.
    let mut config = args
        .resolve(Path::new("unused"), "unused")
        .expect("the flags name every derived value");
    config.options.p2p_disabled = true;
    ethlambda_ethrex::start(config)
        .await
        .expect("the embedded node starts")
}

fn head(hash: H256) -> ForkchoiceStateV1 {
    ForkchoiceStateV1 {
        head_block_hash: hash,
        safe_block_hash: hash,
        finalized_block_hash: hash,
    }
}

fn attributes(timestamp: u64, parent_beacon_block_root: H256) -> PayloadAttributesV3 {
    PayloadAttributesV3 {
        timestamp,
        prev_randao: H256([1; 32]),
        suggested_fee_recipient: H160([2; 20]),
        withdrawals: Vec::new(),
        parent_beacon_block_root,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_osaka_payload_round_trips_through_the_in_process_engine() {
    let node = embedded("genesis-osaka.json", &[]).await;
    let engine = EngineClient::in_process(node.rpc_context());
    let (genesis_hash, genesis_time) = genesis("genesis-osaka.json");

    let capabilities = engine
        .exchange_capabilities(ETHLAMBDA_ENGINE_CAPABILITIES)
        .await
        .expect("an answer");
    for method in [
        "engine_newPayloadV4",
        "engine_forkchoiceUpdatedV3",
        "engine_getPayloadV5",
    ] {
        assert!(capabilities.iter().any(|m| m == method), "{method}");
    }

    let status = engine
        .forkchoice_updated(&head(genesis_hash))
        .await
        .expect("an answer");
    assert_eq!(status.status, PayloadStatusValue::Valid, "{status:?}");

    let parent_beacon_block_root = H256([7; 32]);
    let (status, payload_id) = engine
        .forkchoice_updated_with_attributes(
            &head(genesis_hash),
            &attributes(genesis_time + 12, parent_beacon_block_root),
        )
        .await
        .expect("an answer");
    assert_eq!(status.status, PayloadStatusValue::Valid, "{status:?}");
    let payload_id = payload_id.expect("ethrex builds on a VALID head");

    let built = engine.get_payload(payload_id).await.expect("the build");
    let payload = built.execution_payload;
    assert_eq!(payload.parent_hash, genesis_hash);
    assert_eq!(payload.timestamp, genesis_time + 12);

    // A claimed hash ethrex cannot rebuild is refused: the typed path hands
    // over the consensus layer's hash, not one recomputed from the payload.
    let mut forged = payload.clone();
    forged.block_hash = H256([0xab; 32]);
    let status = engine
        .new_payload(
            &forged,
            &[],
            parent_beacon_block_root,
            &built.execution_requests,
        )
        .await
        .expect("an answer");
    assert_eq!(status.status, PayloadStatusValue::Invalid, "{status:?}");

    let status = engine
        .new_payload(
            &payload,
            &[],
            parent_beacon_block_root,
            &built.execution_requests,
        )
        .await
        .expect("an answer");
    assert_eq!(status.status, PayloadStatusValue::Valid, "{status:?}");

    let status = engine
        .forkchoice_updated(&head(payload.block_hash))
        .await
        .expect("an answer");
    assert_eq!(status.status, PayloadStatusValue::Valid, "{status:?}");

    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_payload_with_an_undecodable_transaction_gets_ethrexs_own_verdict() {
    let node = embedded("genesis-osaka.json", &[]).await;
    let engine = EngineClient::in_process(node.rpc_context());
    let (genesis_hash, genesis_time) = genesis("genesis-osaka.json");

    let parent_beacon_block_root = H256([7; 32]);
    let (_, payload_id) = engine
        .forkchoice_updated_with_attributes(
            &head(genesis_hash),
            &attributes(genesis_time + 12, parent_beacon_block_root),
        )
        .await
        .expect("an answer");
    let built = engine
        .get_payload(payload_id.expect("a build"))
        .await
        .expect("the build");

    // An ethrex block cannot carry this, so the in-process transport hands the
    // payload to ethrex's own parser, which answers it as over the wire.
    let garbage = bellatrix::Transaction::try_from(vec![0xff, 0x00, 0x01]).expect("short");
    let mut payload = built.execution_payload;
    payload.transactions = vec![garbage].try_into().expect("one transaction");
    let status = engine
        .new_payload(
            &payload,
            &[],
            parent_beacon_block_root,
            &built.execution_requests,
        )
        .await
        .expect("an answer");
    assert_eq!(status.status, PayloadStatusValue::Invalid, "{status:?}");

    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_amsterdam_payload_round_trips_through_the_v4_v5_v6_methods() {
    let node = embedded("genesis-amsterdam.json", &[]).await;
    let engine = EngineClient::in_process(node.rpc_context());
    let (genesis_hash, genesis_time) = genesis("genesis-amsterdam.json");

    let status = engine
        .forkchoice_updated_v4(&head(genesis_hash), None)
        .await
        .expect("an answer");
    assert_eq!(status.status, PayloadStatusValue::Valid, "{status:?}");

    let parent_beacon_block_root = H256([9; 32]);
    let attributes = PayloadAttributesV4 {
        v3: attributes(genesis_time + 12, parent_beacon_block_root),
        slot_number: 1,
        target_gas_limit: 30_000_000,
    };
    let (status, payload_id) = engine
        .forkchoice_updated_v4_with_attributes(&head(genesis_hash), &attributes, None)
        .await
        .expect("an answer");
    assert_eq!(status.status, PayloadStatusValue::Valid, "{status:?}");

    let built = engine
        .get_payload_v6(payload_id.expect("ethrex builds on a VALID head"))
        .await
        .expect("the build");
    let payload = built.execution_payload;
    assert_eq!(payload.parent_hash, genesis_hash);
    assert_eq!(payload.slot_number, 1);

    let status = engine
        .new_payload_v5(
            &payload,
            &[],
            parent_beacon_block_root,
            &built.execution_requests,
        )
        .await
        .expect("an answer");
    assert_eq!(status.status, PayloadStatusValue::Valid, "{status:?}");

    let status = engine
        .forkchoice_updated_v4(&head(payload.block_hash), None)
        .await
        .expect("an answer");
    assert_eq!(status.status, PayloadStatusValue::Valid, "{status:?}");

    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_v4_payload_past_amsterdam_is_refused_with_the_wire_code() {
    let node = embedded("genesis-amsterdam.json", &[]).await;
    let engine = EngineClient::in_process(node.rpc_context());
    let (genesis_hash, genesis_time) = genesis("genesis-amsterdam.json");

    let attributes = PayloadAttributesV4 {
        v3: attributes(genesis_time + 12, H256([9; 32])),
        slot_number: 1,
        target_gas_limit: 30_000_000,
    };
    let (_, payload_id) = engine
        .forkchoice_updated_v4_with_attributes(&head(genesis_hash), &attributes, None)
        .await
        .expect("an answer");
    let built = engine
        .get_payload_v6(payload_id.expect("a build"))
        .await
        .expect("the build");

    // Re-cast as deneb's shape and sent as V4, which Amsterdam refuses with
    // `-38005 Unsupported fork`: an `RpcErr` that must surface with the code
    // a JSON-RPC client would read.
    let gloas = built.execution_payload;
    let deneb_shaped = ethlambda_types::beacon::containers::deneb::ExecutionPayload {
        parent_hash: gloas.parent_hash,
        fee_recipient: gloas.fee_recipient,
        state_root: gloas.state_root,
        receipts_root: gloas.receipts_root,
        logs_bloom: gloas.logs_bloom,
        prev_randao: gloas.prev_randao,
        block_number: gloas.block_number,
        gas_limit: gloas.gas_limit,
        gas_used: gloas.gas_used,
        timestamp: gloas.timestamp,
        extra_data: gloas.extra_data,
        base_fee_per_gas: gloas.base_fee_per_gas,
        block_hash: gloas.block_hash,
        transactions: Default::default(),
        withdrawals: Default::default(),
        blob_gas_used: gloas.blob_gas_used,
        excess_blob_gas: gloas.excess_blob_gas,
    };
    let err = engine
        .new_payload(&deneb_shaped, &[], H256([9; 32]), &built.execution_requests)
        .await
        .expect_err("V4 is not Amsterdam's newPayload");
    assert!(
        matches!(err, EngineError::Rpc { code: -38005, .. }),
        "{err:?}"
    );

    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_execution_json_rpc_server_answers_eth_and_refuses_engine() {
    let node = embedded("genesis-osaka.json", &["--ethrex.http-port", "0"]).await;
    let url = format!("http://{}", node.http_addr().expect("the server runs"));
    let client = reqwest::Client::new();

    let chain_id: serde_json::Value = client
        .post(&url)
        .json(
            &serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}),
        )
        .send()
        .await
        .expect("an answer")
        .json()
        .await
        .expect("JSON");
    assert_eq!(chain_id["result"], "0x9", "{chain_id}");
    assert_eq!(chain_id["id"], 1);

    let batch: serde_json::Value = client
        .post(&url)
        .json(&serde_json::json!([
            {"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []},
            {"jsonrpc": "2.0", "id": "two", "method": "engine_exchangeCapabilities", "params": [[]]},
        ]))
        .send()
        .await
        .expect("an answer")
        .json()
        .await
        .expect("JSON");
    let answers = batch.as_array().expect("one answer per request");
    assert_eq!(answers.len(), 2);
    assert_eq!(answers[0]["result"], "0x0", "{batch}");
    assert_eq!(answers[1]["id"], "two");
    assert!(
        answers[1]["error"].is_object(),
        "engine_* must not be served: {batch}"
    );

    let empty: serde_json::Value = client
        .post(&url)
        .json(&serde_json::json!([]))
        .send()
        .await
        .expect("an answer")
        .json()
        .await
        .expect("JSON");
    assert!(empty["error"].is_object(), "{empty}");

    node.shutdown().await;
}
