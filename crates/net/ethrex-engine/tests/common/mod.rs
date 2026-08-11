//! Shared test scaffolding: bootstrapping an engine and signing transactions.
//!
//! Signing lives here because the mempool recovers the sender from the
//! signature, so no transaction test can use an unsigned placeholder.

use ethlambda_ethrex_engine::EthrexEngine;
use ethrex_common::{
    Address, Bytes, U256,
    types::{EIP1559Transaction, Genesis, Transaction, TxKind},
    utils::keccak,
};
use ethrex_rlp::structs::Encoder;
use secp256k1::{Message, SECP256K1, SecretKey};

pub const GENESIS_JSON: &str = include_str!("../fixtures/genesis.json");

/// Secret key for `0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266`, the account the
/// genesis fixture funds for testing. This is the standard Hardhat/Anvil
/// account #0 — deliberately a well-known key, since it only ever holds devnet
/// funds and being recognisable makes it easy to spend from by hand.
///
/// The fixture's other 20 prefunded accounts come from ethrex's
/// `execution-api.json` and we do not hold their keys (checked against all three
/// of ethrex's `fixtures/keys/private_keys*.txt`), which is why this entry
/// exists at all. `funded_account_is_prefunded_in_genesis` asserts the pairing,
/// so a genesis change cannot silently leave every transaction test unfunded.
pub const FUNDED_SECRET_KEY: [u8; 32] =
    hex_to_32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

/// `const`-evaluated hex decode, so the key above stays readable.
const fn hex_to_32(hex: &str) -> [u8; 32] {
    let bytes = hex.as_bytes();
    assert!(bytes.len() == 64, "expected 64 hex chars");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(bytes[i * 2]) * 16 + nibble(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("not a hex digit"),
    }
}

pub fn genesis() -> Genesis {
    serde_json::from_str(GENESIS_JSON).expect("parse genesis")
}

/// Bootstrap an engine plus the genesis timestamp and chain id its payloads
/// must agree with.
pub async fn engine() -> (EthrexEngine, u64, u64) {
    let genesis = genesis();
    let timestamp = genesis.timestamp;
    let chain_id = genesis.config.chain_id;
    let engine = EthrexEngine::from_genesis(genesis)
        .await
        .expect("bootstrap engine");
    (engine, timestamp, chain_id)
}

pub fn secret_key() -> SecretKey {
    SecretKey::from_byte_array(&FUNDED_SECRET_KEY).expect("valid secp256k1 key")
}

/// Address controlled by [`FUNDED_SECRET_KEY`]: keccak of the uncompressed
/// public key minus its `0x04` tag, low 20 bytes.
pub fn funded_address() -> Address {
    let public_key = secret_key().public_key(SECP256K1);
    let uncompressed = public_key.serialize_uncompressed();
    Address::from_slice(&keccak(&uncompressed[1..]).0[12..])
}

/// Sign a minimal EIP-1559 value transfer from the funded account.
///
/// Returns the canonical (`0x02 || rlp`) encoding, i.e. exactly what
/// `submit_raw_transaction` takes.
pub fn signed_transfer(chain_id: u64, nonce: u64, to: Address, value: u64) -> Vec<u8> {
    signed_transfer_from(&secret_key(), chain_id, nonce, to, value)
}

/// As [`signed_transfer`], but signed by an arbitrary key — used to produce a
/// transaction from an account the genesis does not fund.
///
/// The signing payload mirrors ethrex's own `compute_sender`, which is what will
/// verify it.
pub fn signed_transfer_from(
    key: &SecretKey,
    chain_id: u64,
    nonce: u64,
    to: Address,
    value: u64,
) -> Vec<u8> {
    let mut tx = EIP1559Transaction {
        chain_id,
        nonce,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 100_000_000_000,
        gas_limit: 30_000,
        to: TxKind::Call(to),
        value: U256::from(value),
        data: Bytes::new(),
        access_list: Vec::new(),
        ..Default::default()
    };

    let mut payload = vec![0x02];
    Encoder::new(&mut payload)
        .encode_field(&tx.chain_id)
        .encode_field(&tx.nonce)
        .encode_field(&tx.max_priority_fee_per_gas)
        .encode_field(&tx.max_fee_per_gas)
        .encode_field(&tx.gas_limit)
        .encode_field(&tx.to)
        .encode_field(&tx.value)
        .encode_field(&tx.data)
        .encode_field(&tx.access_list)
        .finish();

    let message = Message::from_digest(keccak(&payload).0);
    let (recovery_id, signature) = SECP256K1
        .sign_ecdsa_recoverable(&message, key)
        .serialize_compact();

    tx.signature_y_parity = i32::from(recovery_id) != 0;
    tx.signature_r = U256::from_big_endian(&signature[..32]);
    tx.signature_s = U256::from_big_endian(&signature[32..]);

    Transaction::EIP1559Transaction(tx).encode_canonical_to_vec()
}
