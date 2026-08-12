//! Shared test scaffolding: bootstrapping an engine and signing transactions.
//!
//! Signing lives here because the mempool recovers the sender from the
//! signature, so no transaction test can use an unsigned placeholder.

// Each test binary compiles this module separately and uses only part of it, so
// the unused rest is expected rather than dead.
#![allow(dead_code)]

use ethlambda_ethrex_engine::EthrexEngine;
use ethrex_common::{
    Address, Bytes, U256,
    types::{
        BYTES_PER_BLOB, Blob, BlobsBundle, EIP1559Transaction, EIP4844Transaction, Genesis,
        Transaction, TxKind, WrappedEIP4844Transaction,
    },
    utils::keccak,
};
use ethrex_rlp::encode::RLPEncode;
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

/// Build a signed, wrapped EIP-4844 transaction carrying one blob.
///
/// Returns `0x03 || rlp([tx, wrapper_version, blobs, commitments, proofs])` —
/// the wire form `submit_raw_transaction` expects, and the same shape
/// `eth_sendRawTransaction` takes.
///
/// `wrapper_version` is 0 because the test genesis is Cancun. Version 1 (cell
/// proofs, EIP-7594) is an Osaka-and-later encoding and is rejected here, which
/// is worth knowing since current tooling tends to emit it.
///
/// The blob's bytes are field elements, so each 32-byte chunk must be below the
/// BLS modulus. Writing only the last byte of each chunk keeps every element
/// trivially in range while still making the blob non-empty.
pub fn signed_blob_transfer(chain_id: u64, nonce: u64, to: Address) -> Vec<u8> {
    let mut blob: Blob = [0u8; BYTES_PER_BLOB];
    for (i, chunk) in blob.chunks_mut(32).enumerate() {
        chunk[31] = (i % 251) as u8;
    }

    let blobs_bundle = BlobsBundle::create_from_blobs(&vec![blob], Some(0))
        .expect("KZG commitments and proofs for one blob");
    let blob_versioned_hashes = blobs_bundle.generate_versioned_hashes();

    let mut tx = EIP4844Transaction {
        chain_id,
        nonce,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 100_000_000_000,
        gas: 100_000,
        to,
        value: U256::zero(),
        data: Bytes::new(),
        access_list: Vec::new(),
        max_fee_per_blob_gas: U256::from(1_000_000_000u64),
        blob_versioned_hashes,
        ..Default::default()
    };

    let mut payload = vec![0x03];
    Encoder::new(&mut payload)
        .encode_field(&tx.chain_id)
        .encode_field(&tx.nonce)
        .encode_field(&tx.max_priority_fee_per_gas)
        .encode_field(&tx.max_fee_per_gas)
        .encode_field(&tx.gas)
        .encode_field(&tx.to)
        .encode_field(&tx.value)
        .encode_field(&tx.data)
        .encode_field(&tx.access_list)
        .encode_field(&tx.max_fee_per_blob_gas)
        .encode_field(&tx.blob_versioned_hashes)
        .finish();

    let message = Message::from_digest(keccak(&payload).0);
    let (recovery_id, signature) = SECP256K1
        .sign_ecdsa_recoverable(&message, &secret_key())
        .serialize_compact();

    tx.signature_y_parity = i32::from(recovery_id) != 0;
    tx.signature_r = U256::from_big_endian(&signature[..32]);
    tx.signature_s = U256::from_big_endian(&signature[32..]);

    let wrapped = WrappedEIP4844Transaction {
        tx,
        wrapper_version: Some(0),
        blobs_bundle,
    };
    let mut raw = vec![0x03];
    wrapped.encode(&mut raw);
    raw
}
