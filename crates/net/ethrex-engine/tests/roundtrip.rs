//! End-to-end roundtrip: bootstrap from genesis, build a block in-process,
//! execute/import it, and confirm fork choice advances the canonical head.

use ethlambda_ethrex_engine::EthrexEngine;
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
