//! `ExecutionPayloadV3` ⇄ ethrex `Block` conversion.
//!
//! Mirrors ethrex-rpc's `ExecutionPayload::{into_block, from_block}` but works
//! against `ethrex-common` directly so this crate stays free of the ethrex-rpc
//! dependency (which drags in axum + p2p). The ethlambda `ExecutionPayloadV3`
//! is the Cancun/V3 shape, so the Prague+ header fields (`requests_hash`,
//! `slot_number`, `block_access_list_hash`) round-trip as `None`.

use ethrex_common::{
    Address, Bloom, Bytes, H256, NativeCrypto,
    constants::DEFAULT_OMMERS_HASH,
    types::{
        Block, BlockBody, BlockHeader, Transaction, Withdrawal, compute_transactions_root,
        compute_withdrawals_root,
    },
};

use ethlambda_types::execution_payload::{
    ExecutionPayloadV3, MAX_BYTES_PER_TRANSACTION, Transactions, Withdrawal as LeanWithdrawal,
    Withdrawals,
};
use ethlambda_types::primitives::{ByteList, H256 as LeanH256};

use crate::EngineError;

/// ethlambda `H256` → ethrex `H256`. Both wrap a `[u8; 32]`.
fn to_ethrex_h256(h: &LeanH256) -> H256 {
    H256(h.0)
}

/// ethrex `H256` → ethlambda `H256`.
fn to_lean_h256(h: &H256) -> LeanH256 {
    LeanH256(h.0)
}

/// Build an ethrex [`Block`] from an [`ExecutionPayloadV3`] plus the beacon
/// root supplied alongside it (mirrors ethrex `ExecutionPayload::into_block`).
pub fn payload_to_block(
    payload: &ExecutionPayloadV3,
    parent_beacon_block_root: LeanH256,
) -> Result<Block, EngineError> {
    let crypto = NativeCrypto;

    let transactions = payload
        .transactions
        .iter()
        .map(|raw| Transaction::decode_canonical(&raw[..]))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| EngineError::Conversion(format!("decode transaction: {err}")))?;

    let withdrawals: Vec<Withdrawal> = payload
        .withdrawals
        .iter()
        .map(|w| Withdrawal {
            index: w.index,
            validator_index: w.validator_index,
            address: Address::from_slice(&w.address),
            amount: w.amount,
        })
        .collect();

    let transactions_root = compute_transactions_root(&transactions, &crypto);
    let withdrawals_root = compute_withdrawals_root(&withdrawals, &crypto);

    // ethlambda carries base fee as a 32-byte big-endian `QUANTITY`; ethrex
    // stores it as `Option<u64>`. Base fee always fits in `u64`, so take the
    // low 8 bytes.
    let base_fee_per_gas = u64::from_be_bytes(
        payload.base_fee_per_gas[24..32]
            .try_into()
            .expect("8-byte slice from a 32-byte array"),
    );

    let body = BlockBody {
        transactions,
        ommers: vec![],
        withdrawals: Some(withdrawals),
    };
    let header = BlockHeader {
        parent_hash: to_ethrex_h256(&payload.parent_hash),
        ommers_hash: *DEFAULT_OMMERS_HASH,
        coinbase: Address::from_slice(&payload.fee_recipient),
        state_root: to_ethrex_h256(&payload.state_root),
        transactions_root,
        receipts_root: to_ethrex_h256(&payload.receipts_root),
        logs_bloom: Bloom::from_slice(&payload.logs_bloom),
        difficulty: 0.into(),
        number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: Bytes::copy_from_slice(&payload.extra_data[..]),
        prev_randao: to_ethrex_h256(&payload.prev_randao),
        nonce: 0,
        base_fee_per_gas: Some(base_fee_per_gas),
        withdrawals_root: Some(withdrawals_root),
        blob_gas_used: Some(payload.blob_gas_used),
        excess_blob_gas: Some(payload.excess_blob_gas),
        parent_beacon_block_root: Some(to_ethrex_h256(&parent_beacon_block_root)),
        // V3 payloads predate these Prague+ header fields.
        requests_hash: None,
        ..Default::default()
    };

    Ok(Block::new(header, body))
}

/// Project an ethrex [`Block`] into an [`ExecutionPayloadV3`] (mirrors ethrex
/// `ExecutionPayload::from_block`).
pub fn block_to_payload(block: Block) -> ExecutionPayloadV3 {
    // Compute the hash first: the header caches it, and later field extraction
    // borrows `block` immutably throughout.
    let block_hash = to_lean_h256(&block.hash());

    let mut base_fee_per_gas = [0u8; 32];
    base_fee_per_gas[24..32].copy_from_slice(
        &block
            .header
            .base_fee_per_gas
            .unwrap_or_default()
            .to_be_bytes(),
    );

    let transactions_vec: Vec<ByteList<MAX_BYTES_PER_TRANSACTION>> = block
        .body
        .transactions
        .iter()
        .map(|tx| {
            ByteList::try_from(tx.encode_canonical_to_vec())
                .expect("encoded transaction fits MAX_BYTES_PER_TRANSACTION")
        })
        .collect();
    let transactions = Transactions::try_from(transactions_vec)
        .expect("transaction count fits MAX_TRANSACTIONS_PER_PAYLOAD");

    let withdrawals_vec: Vec<LeanWithdrawal> = block
        .body
        .withdrawals
        .iter()
        .flatten()
        .map(|w| LeanWithdrawal {
            index: w.index,
            validator_index: w.validator_index,
            address: w.address.0,
            amount: w.amount,
        })
        .collect();
    let withdrawals =
        Withdrawals::try_from(withdrawals_vec).expect("withdrawal count fits the payload bound");

    let extra_data = ByteList::try_from(block.header.extra_data.to_vec()).unwrap_or_default();

    ExecutionPayloadV3 {
        parent_hash: to_lean_h256(&block.header.parent_hash),
        fee_recipient: block.header.coinbase.0,
        state_root: to_lean_h256(&block.header.state_root),
        receipts_root: to_lean_h256(&block.header.receipts_root),
        logs_bloom: block.header.logs_bloom.0,
        prev_randao: to_lean_h256(&block.header.prev_randao),
        block_number: block.header.number,
        gas_limit: block.header.gas_limit,
        gas_used: block.header.gas_used,
        timestamp: block.header.timestamp,
        extra_data,
        base_fee_per_gas,
        block_hash,
        transactions,
        withdrawals,
        blob_gas_used: block.header.blob_gas_used.unwrap_or_default(),
        excess_blob_gas: block.header.excess_blob_gas.unwrap_or_default(),
    }
}
