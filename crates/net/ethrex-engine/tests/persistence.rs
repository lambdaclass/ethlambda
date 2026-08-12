//! What a restart does and does not preserve in the execution layer.
//!
//! Block import is gated on execution, so an execution layer that cannot extend
//! the consensus head drops every block it receives — permanently. These tests
//! pin down what survives a restart, and therefore what has to be rebuilt:
//!
//! - the block index and canonical head **do** persist,
//! - executable state does **not**, so the head is present but unbuildable,
//! - replaying payloads in order restores it.
//!
//! That middle point is why gap detection asks "can I build on this?" rather than
//! "do I have this?" — the two answers differ after a restart, and only the first
//! one is useful.

mod common;

use common::{engine, genesis, signed_transfer};
use ethlambda_ethrex_engine::EthrexEngine;
use ethlambda_types::primitives::H256 as LeanH256;
use ethrex_common::Address;

const RECIPIENT: Address = Address::repeat_byte(0x42);

/// A unique directory per test, so parallel runs do not share a RocksDB.
fn store_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ethlambda-el-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Reopening a persistent store keeps the block index but NOT executable state.
///
/// The first half is what an in-memory store loses entirely — it comes back at
/// block 0, which is what bricked a restarted node. The second half is why
/// persistence alone is not the whole fix.
#[tokio::test]
async fn reopening_keeps_blocks_but_not_their_state() {
    let dir = store_dir("survives");
    let genesis_timestamp = genesis().timestamp;
    let chain_id = genesis().config.chain_id;

    let head_after_first_run = {
        let engine = EthrexEngine::from_genesis_path(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/genesis.json"),
            Some(dir.as_path()),
        )
        .await
        .expect("bootstrap with a persistent store");

        let genesis_hash = engine.head_hash().await.unwrap();
        let raw = signed_transfer(chain_id, 0, RECIPIENT, 1);
        engine.submit_raw_transaction(&raw).await.expect("submit");

        let payload = engine
            .build_payload(
                genesis_hash,
                genesis_timestamp + 12,
                LeanH256::ZERO,
                genesis_hash,
                [0u8; 20],
            )
            .await
            .expect("build");
        engine
            .execute_payload(&payload, genesis_hash)
            .expect("execute");
        engine
            .set_head(payload.block_hash, payload.block_hash, genesis_hash)
            .await
            .expect("set head");

        assert_eq!(engine.head_number().await.unwrap(), 1);
        payload.block_hash
    }; // engine dropped — stands in for the process exiting

    // Reopen the same directory, as a restarted node does.
    let reopened = EthrexEngine::from_genesis_path(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/genesis.json"),
        Some(dir.as_path()),
    )
    .await
    .expect("reopen the persistent store");

    assert_eq!(
        reopened.head_number().await.unwrap(),
        1,
        "a reopened store must still be at block 1; 0 means the restart lost everything"
    );
    assert_eq!(
        reopened.head_hash().await.unwrap(),
        head_after_first_run,
        "and at the same block"
    );
    // ...but the block's *state* does not come back with it. ethrex keeps a
    // path-based state trie, and its nodes are not recoverable from a reopened
    // datadir, so the block header and canonical index survive while the
    // post-state does not.
    //
    // This is exactly why `can_build_on` tests state reachability and not merely
    // header presence: a predicate that only asked "is the block here?" would
    // answer yes, conclude there is no gap, and leave the node unable to build —
    // which is the failure this whole mechanism exists to prevent.
    // Recovery is by replay: `a_fresh_engine_can_replay_a_chain_of_payloads`
    // covers the mechanism, and `el_sync` drives it at startup.
    assert!(
        !reopened.can_build_on(head_after_first_run).await.unwrap(),
        "state is expected NOT to survive a reopen; if this now passes, ethrex \
         gained durable state and the startup replay can be skipped when in sync"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `can_build_on` distinguishes blocks the execution layer can extend from those
/// it cannot, which is what bounds the replay to the size of the gap.
#[tokio::test]
async fn can_build_on_reports_only_executable_blocks() {
    let (engine, genesis_timestamp, chain_id) = engine().await;
    let genesis_hash = engine.head_hash().await.unwrap();

    assert!(
        engine.can_build_on(genesis_hash).await.unwrap(),
        "the genesis block is present from the start"
    );
    assert!(
        !engine.can_build_on(LeanH256([0xcd; 32])).await.unwrap(),
        "an unknown hash is absent"
    );

    let raw = signed_transfer(chain_id, 0, RECIPIENT, 1);
    engine.submit_raw_transaction(&raw).await.expect("submit");
    let payload = engine
        .build_payload(
            genesis_hash,
            genesis_timestamp + 12,
            LeanH256::ZERO,
            genesis_hash,
            [0u8; 20],
        )
        .await
        .expect("build");

    assert!(
        !engine.can_build_on(payload.block_hash).await.unwrap(),
        "a built-but-unexecuted payload is not in the store yet"
    );
    engine
        .execute_payload(&payload, genesis_hash)
        .expect("execute");
    assert!(
        engine.can_build_on(payload.block_hash).await.unwrap(),
        "executing it makes it present"
    );
}

/// A fresh engine can execute a chain of payloads produced by another engine, in
/// order — which is exactly what replaying from the Lean chain does.
#[tokio::test]
async fn a_fresh_engine_can_replay_a_chain_of_payloads() {
    let (proposer, genesis_timestamp, chain_id) = engine().await;
    let genesis_hash = proposer.head_hash().await.unwrap();

    // Build three linked blocks, as the network would over three slots.
    let mut payloads = Vec::new();
    let mut parent = genesis_hash;
    for nonce in 0..3u64 {
        let raw = signed_transfer(chain_id, nonce, RECIPIENT, 1);
        proposer.submit_raw_transaction(&raw).await.expect("submit");
        let payload = proposer
            .build_payload(
                parent,
                genesis_timestamp + 12 * (nonce + 1),
                LeanH256::ZERO,
                parent,
                [0u8; 20],
            )
            .await
            .expect("build");
        proposer.execute_payload(&payload, parent).expect("execute");
        proposer
            .set_head(payload.block_hash, payload.block_hash, genesis_hash)
            .await
            .unwrap();
        payloads.push((payload.clone(), parent));
        parent = payload.block_hash;
    }

    // A node restarting with no execution state replays them oldest-first.
    let (restarted, _, _) = engine().await;
    assert_eq!(
        restarted.head_number().await.unwrap(),
        0,
        "starts at genesis"
    );

    for (payload, parent_root) in &payloads {
        restarted
            .execute_payload(payload, *parent_root)
            .expect("replay in order");
    }

    let (last, _) = payloads.last().unwrap();
    restarted
        .set_head(last.block_hash, last.block_hash, genesis_hash)
        .await
        .unwrap();
    assert_eq!(
        restarted.head_number().await.unwrap(),
        3,
        "the replayed node reaches the same height"
    );
    assert_eq!(
        restarted.head_hash().await.unwrap(),
        last.block_hash,
        "and the same block, so consensus can build on it"
    );
}
