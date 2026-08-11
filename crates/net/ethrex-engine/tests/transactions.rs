//! Transactions through the embedded execution layer: submission, inclusion,
//! and the mempool bookkeeping that inclusion depends on.

mod common;

use common::{engine, funded_address, genesis, signed_transfer, signed_transfer_from};
use ethlambda_types::primitives::H256 as LeanH256;
use ethrex_common::Address;

/// Empty-trie root: `receipts_root` of a block that executed nothing. A block
/// that actually ran a transaction must differ from this.
const EMPTY_TRIE_ROOT: [u8; 32] =
    hex_literal(b"56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");

const fn hex_literal(hex: &[u8; 64]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(hex[i * 2]) * 16 + nibble(hex[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("not a lowercase hex digit"),
    }
}

const RECIPIENT: Address = Address::repeat_byte(0x42);

/// The account the transaction tests spend from must actually be funded in the
/// genesis fixture. Guards against a genesis swap turning every assertion below
/// into a vacuous "transaction rejected".
#[test]
fn funded_account_is_prefunded_in_genesis() {
    let address = funded_address();
    let genesis = genesis();
    let account = genesis
        .alloc
        .get(&address)
        .unwrap_or_else(|| panic!("{address:#x} is not in the genesis alloc"));
    assert!(
        account.balance > 10u64.pow(18).into(),
        "{address:#x} holds {} wei, too little to send anything",
        account.balance
    );
}

/// The whole path: submit → included in the next built payload → executed.
#[tokio::test]
async fn submitted_transaction_is_included_and_executed() {
    let (engine, genesis_timestamp, chain_id) = engine().await;
    let genesis_hash = engine.head_hash().await.unwrap();

    let raw = signed_transfer(chain_id, 0, RECIPIENT, 1);
    let tx_hash = engine
        .submit_raw_transaction(&raw)
        .await
        .expect("mempool accepts a signed, funded transfer");

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

    assert_eq!(
        payload.transactions.len(),
        1,
        "the pooled transaction must be packed into the block"
    );
    assert_eq!(
        payload.transactions[0][..].to_vec(),
        raw,
        "packed transaction must be the one submitted, byte for byte"
    );
    assert!(payload.gas_used > 0, "executing a transfer must burn gas");
    assert_ne!(
        payload.receipts_root.0, EMPTY_TRIE_ROOT,
        "a block with a transaction must have a non-empty receipts trie"
    );

    engine
        .execute_payload(&payload, genesis_hash)
        .expect("EL accepts its own payload");

    // Sanity: the hash we handed back is the one that landed.
    assert_eq!(
        payload.transactions[0][..].to_vec(),
        raw,
        "submitted hash {tx_hash:?} corresponds to the included bytes"
    );
}

/// Three transactions from one sender land in three consecutive blocks.
///
/// This is the regression test for mempool eviction on import. Without it the
/// included transaction stays pooled; the next build re-fetches it (the builder
/// applies no nonce filter), its re-execution fails on the stale nonce, and
/// ethrex's `pop()` drops *every* transaction from that sender — so nonce 1
/// would never be included by any node, in any slot. The symptom is "each
/// account can send exactly one transaction, ever".
#[tokio::test]
async fn sequential_transactions_from_one_sender_land_in_consecutive_blocks() {
    let (engine, genesis_timestamp, chain_id) = engine().await;

    let mut parent = engine.head_hash().await.unwrap();

    for nonce in 0..3u64 {
        let raw = signed_transfer(chain_id, nonce, RECIPIENT, 1);
        engine
            .submit_raw_transaction(&raw)
            .await
            .unwrap_or_else(|err| panic!("submit nonce {nonce}: {err}"));

        let payload = engine
            .build_payload(
                parent,
                genesis_timestamp + 12 * (nonce + 1),
                LeanH256::ZERO,
                parent,
                [0u8; 20],
            )
            .await
            .unwrap_or_else(|err| panic!("build block for nonce {nonce}: {err}"));

        assert_eq!(
            payload.transactions.len(),
            1,
            "block {} must carry exactly the one pending transaction (nonce {nonce}); \
             carrying 0 means the sender's queue was dropped, >1 means a stale copy \
             was re-packed",
            nonce + 1
        );
        assert_eq!(
            payload.transactions[0][..].to_vec(),
            raw,
            "block {} must carry nonce {nonce}, not a replay of an earlier one",
            nonce + 1
        );

        engine
            .execute_payload(&payload, parent)
            .unwrap_or_else(|err| panic!("execute block for nonce {nonce}: {err}"));

        parent = payload.block_hash;
        engine.set_head(parent, parent, parent).await.unwrap();
    }

    assert_eq!(
        engine.head_number().await.unwrap(),
        3,
        "three transactions, three blocks"
    );
}

/// A payload whose `block_hash` does not describe its contents is rejected.
///
/// Every other header field is rebuilt from the payload, so the claimed hash is
/// the only thing tying the two together. Accepting a mismatch would let each
/// node's execution layer store a different block under a hash consensus has
/// already committed to, after which no node could build on it.
#[tokio::test]
async fn rejects_payload_whose_block_hash_does_not_match_its_contents() {
    let (engine, genesis_timestamp, chain_id) = engine().await;
    let genesis_hash = engine.head_hash().await.unwrap();

    let raw = signed_transfer(chain_id, 0, RECIPIENT, 1);
    engine.submit_raw_transaction(&raw).await.expect("submit");

    let mut payload = engine
        .build_payload(
            genesis_hash,
            genesis_timestamp + 12,
            LeanH256::ZERO,
            genesis_hash,
            [0u8; 20],
        )
        .await
        .expect("build payload");

    // Tamper with the claim only; the contents stay valid and executable.
    payload.block_hash = LeanH256([0xab; 32]);

    let err = engine
        .execute_payload(&payload, genesis_hash)
        .expect_err("a payload that lies about its own hash must be rejected");
    assert!(
        err.to_string().contains("claims block hash"),
        "expected a block-hash mismatch, got: {err}"
    );
}

/// Regenerate the hex fixtures the RPC crate's submit-endpoint tests post.
///
/// Those tests need a validly signed transaction but should not pull in
/// secp256k1 just to make one, so they read a checked-in hex file instead. This
/// is the generator, ignored by default:
///
/// ```text
/// cargo test -p ethlambda-ethrex-engine --profile release-fast \
///   --test transactions -- --ignored regenerate_rpc_fixtures --nocapture
/// ```
///
/// Rerun it if the genesis chain id or the funded account changes.
#[test]
#[ignore = "writes fixture files; run explicitly when the genesis changes"]
fn regenerate_rpc_fixtures() {
    let chain_id = genesis().config.chain_id;
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../rpc/tests/fixtures");
    std::fs::create_dir_all(dir).expect("create fixtures dir");

    let funded = signed_transfer(chain_id, 0, RECIPIENT, 1);
    std::fs::write(
        format!("{dir}/signed_transfer_nonce_0.hex"),
        format!("0x{}\n", hex_encode(&funded)),
    )
    .expect("write funded fixture");

    // An account the genesis does not fund, so the mempool rejects it for
    // balance rather than for anything about its signature.
    let unfunded = secp256k1::SecretKey::from_byte_array(&[0x11; 32]).expect("valid key");
    let broke = signed_transfer_from(&unfunded, chain_id, 0, RECIPIENT, 1);
    std::fs::write(
        format!("{dir}/signed_transfer_unfunded.hex"),
        format!("0x{}\n", hex_encode(&broke)),
    )
    .expect("write unfunded fixture");

    println!("wrote 2 fixtures to {dir} (chain_id {chain_id})");
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
