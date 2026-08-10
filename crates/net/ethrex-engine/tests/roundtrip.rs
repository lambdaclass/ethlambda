//! End-to-end: bootstrap an embedded ethrex from genesis, build a payload,
//! execute it, and confirm the execution layer's head advances.

use ethlambda_ethrex_engine::EthrexEngine;
use ethlambda_types::primitives::H256 as LeanH256;
use ethrex_common::types::Genesis;

const GENESIS_JSON: &str = include_str!("fixtures/genesis.json");

async fn engine() -> (EthrexEngine, u64) {
    let genesis: Genesis = serde_json::from_str(GENESIS_JSON).expect("parse genesis");
    let genesis_timestamp = genesis.timestamp;
    let engine = EthrexEngine::from_genesis(genesis)
        .await
        .expect("bootstrap engine");
    (engine, genesis_timestamp)
}

/// The whole in-process cycle: build a payload for the next block, execute it,
/// then move the head onto it. Exercises the payload ⇄ block conversion in both
/// directions, with the execution layer judging its own output.
#[tokio::test]
async fn builds_executes_and_advances_head() {
    let (engine, genesis_timestamp) = engine().await;

    assert_eq!(engine.head_number().await.unwrap(), 0, "starts at genesis");
    let genesis_hash = engine.head_hash().await.unwrap();

    let payload = engine
        .build_payload(
            genesis_hash,
            genesis_timestamp + 12,
            LeanH256::ZERO,
            genesis_hash,
            [0u8; 20],
        )
        .await
        .expect("build payload");
    assert_eq!(payload.block_number, 1, "built payload is height 1");
    assert_ne!(
        payload.block_hash,
        LeanH256::ZERO,
        "built payload carries a real block hash"
    );
    let block_hash = payload.block_hash;

    // The EL must accept the payload it just produced. This is the check that
    // catches conversion mistakes and fork-config mismatches (a Prague genesis
    // fails here, because V3 cannot carry the requests_hash it demands).
    engine
        .execute_payload(&payload, genesis_hash)
        .expect("EL accepts its own payload");

    engine
        .set_head(block_hash, block_hash, genesis_hash)
        .await
        .expect("apply fork choice");

    assert_eq!(engine.head_number().await.unwrap(), 1);
    assert_eq!(engine.head_hash().await.unwrap(), block_hash);
}

/// A payload whose beacon root does not match the one it was built with is
/// rejected: the root is committed to in the block hash.
#[tokio::test]
async fn rejects_payload_with_mismatched_beacon_root() {
    let (engine, genesis_timestamp) = engine().await;
    let genesis_hash = engine.head_hash().await.unwrap();

    let payload = engine
        .build_payload(
            genesis_hash,
            genesis_timestamp + 12,
            LeanH256::ZERO,
            genesis_hash,
            [0u8; 20],
        )
        .await
        .expect("build payload");

    let wrong_root = LeanH256([9u8; 32]);
    assert!(
        engine.execute_payload(&payload, wrong_root).is_err(),
        "a payload replayed under a different beacon root must not be accepted"
    );
}

/// The payload must be built on the parent the caller names, not on whatever
/// this engine's own canonical head happens to be.
///
/// Every node runs its own execution layer, so a proposer's EL head can drift
/// from the consensus chain. The state transition checks a new payload's
/// `parent_hash` against `state.latest_execution_payload_header.block_hash`, so
/// building on the wrong parent produces a block every peer rejects — which
/// stalls finality without any error surfacing locally.
#[tokio::test]
async fn builds_on_the_requested_parent_not_the_el_head() {
    let (engine, genesis_timestamp) = engine().await;
    let genesis_hash = engine.head_hash().await.unwrap();

    // Advance the EL two blocks, so its head is no longer genesis.
    let mut parent = genesis_hash;
    let mut block_1 = LeanH256::ZERO;
    for i in 1..=2u64 {
        let payload = engine
            .build_payload(
                parent,
                genesis_timestamp + 12 * i,
                LeanH256::ZERO,
                parent,
                [0u8; 20],
            )
            .await
            .expect("build payload");
        engine.execute_payload(&payload, parent).expect("execute");
        parent = payload.block_hash;
        if i == 1 {
            block_1 = parent;
        }
        engine.set_head(parent, parent, genesis_hash).await.unwrap();
    }
    assert_eq!(engine.head_number().await.unwrap(), 2, "EL head advanced");

    // Now ask for a payload extending block 1 (NOT the EL head at block 2), the
    // way a proposer would after a reorg or when its EL ran ahead.
    let payload = engine
        .build_payload(
            block_1,
            genesis_timestamp + 999,
            LeanH256::ZERO,
            block_1,
            [0u8; 20],
        )
        .await
        .expect("build on an explicit non-head parent");

    assert_eq!(
        payload.parent_hash, block_1,
        "payload must name the requested parent, not the EL's own head"
    );
    assert_eq!(payload.block_number, 2, "extending block 1 yields height 2");
}
