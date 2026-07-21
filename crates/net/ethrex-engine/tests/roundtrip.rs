//! End-to-end roundtrip: bootstrap from genesis, build a block in-process,
//! execute/import it, and confirm fork choice advances the canonical head.

use ethlambda_ethrex_client::{
    ExecutionEngine, ForkChoiceState, PayloadAttributesV3, PayloadStatusKind,
};
use ethlambda_ethrex_engine::EthrexEngine;
use ethlambda_types::primitives::H256 as LeanH256;
use ethrex_common::{Address, H256, types::Genesis};

const GENESIS_JSON: &str = include_str!("fixtures/genesis.json");

#[tokio::test]
async fn builds_executes_and_advances_head() {
    let genesis: Genesis = serde_json::from_str(GENESIS_JSON).expect("parse genesis");
    let genesis_timestamp = genesis.timestamp;

    let engine = EthrexEngine::from_genesis(genesis)
        .await
        .expect("bootstrap engine");

    // Genesis is block 0.
    assert_eq!(engine.head_number().await.unwrap(), 0);
    let genesis_hash = engine.head_hash().await.unwrap();

    // Build an (empty, no-mempool) block on top of genesis.
    let block = engine
        .build_block(
            genesis_timestamp + 12,
            H256::zero(),
            genesis_hash,
            Address::zero(),
        )
        .await
        .expect("build block");
    let block_hash = block.hash();
    assert_eq!(block.header.number, 1, "built block is height 1");

    // Execute + import it, then point fork choice at it.
    engine.import_block(block).expect("import block");
    engine
        .set_forkchoice(block_hash, block_hash, genesis_hash)
        .await
        .expect("apply fork choice");

    // The canonical head advanced to the freshly built block.
    assert_eq!(engine.head_number().await.unwrap(), 1);
    assert_eq!(engine.head_hash().await.unwrap(), block_hash);
}

/// Exercises the `ExecutionEngine` trait path (and the payload ⇄ block
/// conversion): build a payload via `forkchoice_updated_v3(Some(attrs))`,
/// fetch it with `get_payload`, then feed it back through `new_payload` and
/// require the EL to accept it.
#[tokio::test]
async fn engine_trait_build_get_new_payload_roundtrip() {
    let genesis: Genesis = serde_json::from_str(GENESIS_JSON).expect("parse genesis");
    let genesis_timestamp = genesis.timestamp;
    let engine = EthrexEngine::from_genesis(genesis)
        .await
        .expect("bootstrap engine");

    // Genesis head, as the ethlambda H256 the trait speaks.
    let genesis_hash = LeanH256(engine.head_hash().await.unwrap().0);

    let state = ForkChoiceState {
        head_block_hash: genesis_hash,
        safe_block_hash: genesis_hash,
        finalized_block_hash: genesis_hash,
    };
    let attrs = PayloadAttributesV3 {
        timestamp: genesis_timestamp + 12,
        prev_randao: LeanH256::ZERO,
        suggested_fee_recipient: [0u8; 20],
        withdrawals: vec![],
        parent_beacon_block_root: genesis_hash,
    };

    let resp = engine
        .forkchoice_updated_v3(state, Some(attrs))
        .await
        .expect("forkchoice_updated build mode");
    let payload_id = resp.payload_id.expect("build returns a payload id");

    let payload = engine.get_payload(payload_id).await.expect("get_payload");
    assert_eq!(payload.block_number, 1, "built payload is height 1");

    let status = engine
        .new_payload(&payload, genesis_hash)
        .await
        .expect("new_payload call");
    assert_eq!(
        status.status,
        PayloadStatusKind::Valid,
        "EL must accept the payload it built; validation_error={:?}",
        status.validation_error
    );
}
