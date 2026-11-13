//! The in-process transport: an embedded ethrex's own Engine API handlers,
//! called as functions.
//!
//! Each request is built as the ethrex handler struct the method names
//! (`NewPayloadV4Request`, `ForkChoiceUpdatedV3`, ...) and run through
//! [`RpcHandler::handle`] against the embedded node's [`RpcApiContext`], so no
//! socket, JWT or JSON request body is involved. The handlers answer with the
//! same `serde_json::Value` they would put on the wire, and that is decoded by
//! the very types the HTTP transport decodes into, so both transports share one
//! reading of every answer.
//!
//! # Building a payload
//!
//! ethrex's `ExecutionPayload` keeps most of its fields crate-private, so it
//! cannot be written as a struct literal here. It is built through its public
//! `from_block` instead: our payload becomes an ethrex [`Block`] whose header
//! carries the payload's fields, and the payload's own `block_hash` replaces the
//! one `from_block` computes, so ethrex still checks the hash the consensus
//! layer claims rather than one recomputed from that claim. The header's roots
//! are left zero: `from_block` reads none of them, and ethrex recomputes them
//! from the transactions and withdrawals when it rebuilds the block.
//!
//! A payload that block cannot represent (a transaction that does not decode,
//! a base fee past `u64`) is handed to the handler's own `parse` instead, from
//! the parameters the HTTP transport would send. Those payloads are the
//! malformed ones, and ethrex's verdict on a malformed payload (`INVALID`, or a
//! `-32602`) is exactly the one it gives over the wire.
//!
//! # No retry ladder
//!
//! The HTTP transport retries a call that got no answer. There is no transport
//! to fail here: every `Err` a handler returns is ethrex's answer, which asking
//! again would only repeat. The per-method timeouts stay, because the chain
//! actor awaits `newPayload` inline during import, and an unbounded wait would
//! stall it for as long as a pathological block takes to execute.

use std::fmt;
use std::time::Duration;

use bytes::Bytes;
use ethlambda_types::beacon::containers::{capella, deneb, gloas};
use ethlambda_types::beacon::primitives::{Bytes32, Root, Uint256};
use ethrex_common::types::block_access_list::BlockAccessList;
use ethrex_common::types::requests::EncodedRequests;
use ethrex_common::types::{Block, BlockBody, BlockHeader, Transaction, Withdrawal};
use ethrex_common::utils::keccak;
use ethrex_common::{Address, Bloom, H256};
use ethrex_rlp::decode::RLPDecode as _;
use ethrex_rpc::engine::ExchangeCapabilitiesRequest;
use ethrex_rpc::engine::client_version::GetClientVersionV1Request;
use ethrex_rpc::engine::fork_choice::{ForkChoiceUpdatedV3, ForkChoiceUpdatedV4};
use ethrex_rpc::engine::payload::{
    GetPayloadV5Request, GetPayloadV6Request, NewPayloadV4Request, NewPayloadV5Request,
};
use ethrex_rpc::types::fork_choice::{ForkChoiceState, PayloadAttributesV3, PayloadAttributesV4};
use ethrex_rpc::types::payload::ExecutionPayload;
use ethrex_rpc::{RpcApiContext, RpcErr, RpcErrorMetadata, RpcHandler};
use serde::de::DeserializeOwned;

use crate::building::{self, PayloadId};
use crate::client::{
    ENGINE_NEW_PAYLOAD_V5_TIMEOUT, ENGINE_TIMEOUT, new_payload_v4_params, new_payload_v5_params,
};
use crate::error::EngineError;
use crate::types::{
    ClientVersionV1, CustodyColumns, ForkchoiceStateV1, ForkchoiceUpdatedResponse, PayloadStatusV1,
};

/// A handle on an embedded ethrex's Engine API: its RPC context, which every
/// handler takes by value.
#[derive(Clone)]
pub(crate) struct InProcessEngine {
    context: RpcApiContext,
}

impl fmt::Debug for InProcessEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The context holds the node's store, chain and peer handles, none of
        // which say anything useful in a log line.
        f.debug_struct("InProcessEngine").finish_non_exhaustive()
    }
}

impl InProcessEngine {
    pub(crate) fn new(context: RpcApiContext) -> Self {
        Self { context }
    }

    /// Runs one handler under `timeout` and decodes its answer as `T`.
    async fn run<H: RpcHandler, T: DeserializeOwned>(
        &self,
        request: H,
        timeout: Duration,
    ) -> Result<T, EngineError> {
        let context = self.context.clone();
        // Boxed as ethrex boxes its own dispatch arms: a `newPayload` handler's
        // future carries a block execution, and inlining it would size every
        // caller's future to it.
        let call = Box::pin(async move { request.handle(context).await });
        let answer = tokio::time::timeout(timeout, call)
            .await
            .map_err(|_| EngineError::Timeout(timeout))?
            .map_err(rpc_error)?;
        serde_json::from_value(answer).map_err(|err| EngineError::Decode(err.to_string()))
    }

    pub(crate) async fn new_payload(
        &self,
        payload: &deneb::ExecutionPayload,
        versioned_hashes: &[Bytes32],
        parent_beacon_block_root: Root,
        execution_requests: &[Vec<u8>],
    ) -> Result<PayloadStatusV1, EngineError> {
        let request = match typed_payload(&PayloadFields::from(payload), None) {
            Some(payload) => NewPayloadV4Request {
                payload,
                expected_blob_versioned_hashes: hashes(versioned_hashes),
                parent_beacon_block_root: h256(&parent_beacon_block_root),
                execution_requests: requests(execution_requests),
            },
            None => parse_wire(new_payload_v4_params(
                payload,
                versioned_hashes,
                parent_beacon_block_root,
                execution_requests,
            ))?,
        };
        self.run(request, ENGINE_TIMEOUT).await
    }

    pub(crate) async fn new_payload_v5(
        &self,
        payload: &gloas::ExecutionPayload,
        versioned_hashes: &[Bytes32],
        parent_beacon_block_root: Root,
        execution_requests: &[Vec<u8>],
    ) -> Result<PayloadStatusV1, EngineError> {
        // What ethrex's `parse` derives from the raw `blockAccessList` DATA: the
        // header commits to the list exactly as it arrived, so its hash is
        // taken over the raw bytes, and a list that does not decode is answered
        // INVALID under the block's own hash rather than refused as malformed
        // params, which is what the flag asks for.
        let raw_bal = payload.block_access_list.as_ref();
        let decoded_bal = decode_block_access_list(raw_bal);
        let undecodable_bal = decoded_bal.is_none();

        let request = match typed_payload(&PayloadFields::from(payload), decoded_bal) {
            Some(typed) => NewPayloadV5Request {
                payload: typed,
                expected_blob_versioned_hashes: hashes(versioned_hashes),
                parent_beacon_block_root: h256(&parent_beacon_block_root),
                execution_requests: requests(execution_requests),
                raw_bal_hash: Some(keccak(raw_bal)),
                undecodable_bal,
            },
            None => parse_wire(new_payload_v5_params(
                payload,
                versioned_hashes,
                parent_beacon_block_root,
                execution_requests,
            ))?,
        };
        self.run(request, ENGINE_NEW_PAYLOAD_V5_TIMEOUT).await
    }

    pub(crate) async fn forkchoice_updated(
        &self,
        state: &ForkchoiceStateV1,
        attributes: Option<&building::PayloadAttributesV3>,
    ) -> Result<ForkchoiceUpdatedResponse, EngineError> {
        let request = ForkChoiceUpdatedV3 {
            fork_choice_state: forkchoice_state(state),
            payload_attributes: attributes.map(payload_attributes_v3),
        };
        self.run(request, ENGINE_TIMEOUT).await
    }

    pub(crate) async fn forkchoice_updated_v4(
        &self,
        state: &ForkchoiceStateV1,
        attributes: Option<&building::PayloadAttributesV4>,
        custody_columns: Option<CustodyColumns>,
    ) -> Result<ForkchoiceUpdatedResponse, EngineError> {
        let request = ForkChoiceUpdatedV4 {
            fork_choice_state: forkchoice_state(state),
            payload_attributes: attributes.map(payload_attributes_v4),
            custody_columns: custody_columns.map(CustodyColumns::to_u128),
        };
        self.run(request, ENGINE_TIMEOUT).await
    }

    pub(crate) async fn get_payload(
        &self,
        payload_id: PayloadId,
    ) -> Result<building::GetPayloadV5Response, EngineError> {
        let request = GetPayloadV5Request {
            payload_id: payload_id_u64(payload_id),
        };
        self.run(request, ENGINE_TIMEOUT).await
    }

    pub(crate) async fn get_payload_v6(
        &self,
        payload_id: PayloadId,
    ) -> Result<building::GetPayloadV6Response, EngineError> {
        let request = GetPayloadV6Request {
            payload_id: payload_id_u64(payload_id),
        };
        self.run(request, ENGINE_TIMEOUT).await
    }

    pub(crate) async fn exchange_capabilities(
        &self,
        ours: &[&str],
    ) -> Result<Vec<String>, EngineError> {
        let request: ExchangeCapabilitiesRequest =
            ours.iter().map(|method| method.to_string()).collect();
        self.run(request, ENGINE_TIMEOUT).await
    }

    pub(crate) async fn client_version(
        &self,
        ours: &ClientVersionV1,
    ) -> Result<Vec<ClientVersionV1>, EngineError> {
        // The request's only field is private, so it is built by its own
        // `parse`. This runs once at startup and for graffiti, never per block.
        let ours =
            serde_json::to_value(ours).map_err(|err| EngineError::Decode(err.to_string()))?;
        let request = GetClientVersionV1Request::parse(&Some(vec![ours])).map_err(rpc_error)?;
        self.run(request, ENGINE_TIMEOUT).await
    }
}

/// An ethrex handler error as the wire would carry it: the same code and
/// message `RpcErrorMetadata` writes into a JSON-RPC `error` object, so a caller
/// matching on a code (`-38006` for too deep a reorg, say) sees no difference
/// between the transports.
fn rpc_error(err: RpcErr) -> EngineError {
    let metadata = RpcErrorMetadata::from(err);
    EngineError::Rpc {
        code: metadata.code.into(),
        message: metadata.message,
    }
}

/// Builds a handler from the positional parameters the HTTP transport sends,
/// through the handler's own `parse`.
fn parse_wire<H: RpcHandler>(params: serde_json::Value) -> Result<H, EngineError> {
    let serde_json::Value::Array(params) = params else {
        unreachable!("the engine parameter builders return a JSON array");
    };
    H::parse(&Some(params)).map_err(rpc_error)
}

/// The fields deneb's and gloas's payloads share, borrowed.
///
/// Gloas's transactions and withdrawals are progressive lists, a different type
/// from deneb's, so the two payloads meet here rather than in one generic.
struct PayloadFields<'a> {
    parent_hash: &'a Bytes32,
    fee_recipient: &'a [u8; 20],
    state_root: &'a Bytes32,
    receipts_root: &'a Bytes32,
    logs_bloom: &'a [u8],
    prev_randao: &'a Bytes32,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: &'a [u8],
    base_fee_per_gas: &'a Uint256,
    block_hash: &'a Bytes32,
    transactions: Vec<&'a [u8]>,
    withdrawals: Vec<&'a capella::Withdrawal>,
    blob_gas_used: u64,
    excess_blob_gas: u64,
    /// Gloas only (EIP-7843).
    slot_number: Option<u64>,
}

impl<'a> From<&'a deneb::ExecutionPayload> for PayloadFields<'a> {
    fn from(payload: &'a deneb::ExecutionPayload) -> Self {
        Self {
            parent_hash: &payload.parent_hash,
            fee_recipient: &payload.fee_recipient.0,
            state_root: &payload.state_root,
            receipts_root: &payload.receipts_root,
            logs_bloom: payload.logs_bloom.as_ref(),
            prev_randao: &payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.as_ref(),
            base_fee_per_gas: &payload.base_fee_per_gas,
            block_hash: &payload.block_hash,
            transactions: payload.transactions.iter().map(|tx| tx.as_ref()).collect(),
            withdrawals: payload.withdrawals.iter().collect(),
            blob_gas_used: payload.blob_gas_used,
            excess_blob_gas: payload.excess_blob_gas,
            slot_number: None,
        }
    }
}

impl<'a> From<&'a gloas::ExecutionPayload> for PayloadFields<'a> {
    fn from(payload: &'a gloas::ExecutionPayload) -> Self {
        Self {
            parent_hash: &payload.parent_hash,
            fee_recipient: &payload.fee_recipient.0,
            state_root: &payload.state_root,
            receipts_root: &payload.receipts_root,
            logs_bloom: payload.logs_bloom.as_ref(),
            prev_randao: &payload.prev_randao,
            block_number: payload.block_number,
            gas_limit: payload.gas_limit,
            gas_used: payload.gas_used,
            timestamp: payload.timestamp,
            extra_data: payload.extra_data.as_ref(),
            base_fee_per_gas: &payload.base_fee_per_gas,
            block_hash: &payload.block_hash,
            transactions: payload.transactions.iter().map(|tx| tx.as_ref()).collect(),
            withdrawals: payload.withdrawals.iter().collect(),
            blob_gas_used: payload.blob_gas_used,
            excess_blob_gas: payload.excess_blob_gas,
            slot_number: Some(payload.slot_number),
        }
    }
}

/// ethrex's `ExecutionPayload` for `fields`, or `None` when an ethrex block
/// cannot carry them: a transaction that does not decode, or a base fee past
/// `u64`. See the module documentation for why `None` is not an error.
fn typed_payload(
    fields: &PayloadFields<'_>,
    block_access_list: Option<BlockAccessList>,
) -> Option<ExecutionPayload> {
    let transactions = fields
        .transactions
        .iter()
        .map(|transaction| Transaction::decode_canonical(transaction))
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let withdrawals = fields
        .withdrawals
        .iter()
        .map(|withdrawal| Withdrawal {
            index: withdrawal.index,
            validator_index: withdrawal.validator_index,
            address: Address::from(withdrawal.address.0),
            amount: withdrawal.amount,
        })
        .collect();

    let header = BlockHeader {
        parent_hash: h256(fields.parent_hash),
        coinbase: Address::from(*fields.fee_recipient),
        state_root: h256(fields.state_root),
        receipts_root: h256(fields.receipts_root),
        logs_bloom: Bloom::from_slice(fields.logs_bloom),
        prev_randao: h256(fields.prev_randao),
        number: fields.block_number,
        gas_limit: fields.gas_limit,
        gas_used: fields.gas_used,
        timestamp: fields.timestamp,
        extra_data: Bytes::copy_from_slice(fields.extra_data),
        base_fee_per_gas: Some(uint256_to_u64(fields.base_fee_per_gas)?),
        blob_gas_used: Some(fields.blob_gas_used),
        excess_blob_gas: Some(fields.excess_blob_gas),
        slot_number: fields.slot_number,
        ..Default::default()
    };
    let body = BlockBody {
        transactions,
        ommers: Vec::new(),
        withdrawals: Some(withdrawals),
    };

    let mut payload = ExecutionPayload::from_block(Block::new(header, body), block_access_list);
    // `from_block` hashes the header it was given, whose roots are zero. The
    // hash ethrex must check is the one the consensus layer claims.
    payload.block_hash = h256(fields.block_hash);
    Some(payload)
}

/// The block access list `raw` encodes, or `None` when it does not decode.
///
/// Empty bytes count as undecodable, as in ethrex's own `parse`: its serde
/// reader takes an empty `0x` for an absent list, but the strict decoder that
/// governs the header hash refuses empty input, and the strict verdict is the
/// one that stands.
fn decode_block_access_list(raw: &[u8]) -> Option<BlockAccessList> {
    if raw.is_empty() {
        return None;
    }
    BlockAccessList::decode(raw).ok()
}

/// A 256-bit little-endian quantity as a `u64`, or `None` past `u64::MAX`.
fn uint256_to_u64(value: &Uint256) -> Option<u64> {
    let (low, high) = value.0.split_at(8);
    if high.iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(u64::from_le_bytes(
        low.try_into().expect("split at eight bytes"),
    ))
}

fn h256(value: &Bytes32) -> H256 {
    H256(value.0)
}

fn hashes(versioned_hashes: &[Bytes32]) -> Vec<H256> {
    versioned_hashes.iter().map(h256).collect()
}

fn requests(execution_requests: &[Vec<u8>]) -> Vec<EncodedRequests> {
    execution_requests
        .iter()
        .map(|request| EncodedRequests(Bytes::copy_from_slice(request)))
        .collect()
}

fn forkchoice_state(state: &ForkchoiceStateV1) -> ForkChoiceState {
    ForkChoiceState {
        head_block_hash: h256(&state.head_block_hash),
        safe_block_hash: h256(&state.safe_block_hash),
        finalized_block_hash: h256(&state.finalized_block_hash),
    }
}

fn withdrawals(withdrawals: &[capella::Withdrawal]) -> Vec<Withdrawal> {
    withdrawals
        .iter()
        .map(|withdrawal| Withdrawal {
            index: withdrawal.index,
            validator_index: withdrawal.validator_index,
            address: Address::from(withdrawal.address.0),
            amount: withdrawal.amount,
        })
        .collect()
}

fn payload_attributes_v3(attributes: &building::PayloadAttributesV3) -> PayloadAttributesV3 {
    PayloadAttributesV3 {
        timestamp: attributes.timestamp,
        prev_randao: h256(&attributes.prev_randao),
        suggested_fee_recipient: Address::from(attributes.suggested_fee_recipient.0),
        withdrawals: Some(withdrawals(&attributes.withdrawals)),
        parent_beacon_block_root: Some(h256(&attributes.parent_beacon_block_root)),
    }
}

fn payload_attributes_v4(attributes: &building::PayloadAttributesV4) -> PayloadAttributesV4 {
    let v3 = &attributes.v3;
    PayloadAttributesV4 {
        timestamp: v3.timestamp,
        prev_randao: h256(&v3.prev_randao),
        suggested_fee_recipient: Address::from(v3.suggested_fee_recipient.0),
        withdrawals: Some(withdrawals(&v3.withdrawals)),
        parent_beacon_block_root: Some(h256(&v3.parent_beacon_block_root)),
        slot_number: attributes.slot_number,
        target_gas_limit: attributes.target_gas_limit,
    }
}

/// A payload id as the `u64` ethrex keys its build processes by. The wire's
/// eight-byte `DATA` is that number big-endian, which is how ethrex parses it.
fn payload_id_u64(payload_id: PayloadId) -> u64 {
    u64::from_be_bytes(payload_id.0)
}

#[cfg(test)]
mod tests {
    use ethlambda_types::beacon::containers::bellatrix;
    use ethlambda_types::beacon::preset;
    use ethlambda_types::beacon::primitives::{H160, H256 as OurH256, U256};
    use ethrex_common::types::EIP1559Transaction;
    use serde::Deserialize as _;

    use super::*;
    use crate::types::{ExecutionPayloadV3, ExecutionPayloadV4};

    /// A type-2 transaction ethrex decodes, as the bytes a payload carries.
    fn transaction_bytes(nonce: u64) -> Vec<u8> {
        Transaction::EIP1559Transaction(EIP1559Transaction {
            nonce,
            gas_limit: 21_000,
            ..Default::default()
        })
        .encode_canonical_to_vec()
    }

    fn withdrawal(index: u64) -> capella::Withdrawal {
        capella::Withdrawal {
            index,
            validator_index: index + 100,
            address: H160([index as u8; 20]),
            amount: index * 1_000,
        }
    }

    /// A deneb payload whose every field holds a distinct value, so a field
    /// mapped to the wrong place shows up.
    fn deneb_payload() -> deneb::ExecutionPayload {
        let transactions = vec![
            bellatrix::Transaction::try_from(transaction_bytes(1)).unwrap(),
            bellatrix::Transaction::try_from(transaction_bytes(2)).unwrap(),
        ];
        deneb::ExecutionPayload {
            parent_hash: OurH256([1; 32]),
            fee_recipient: H160([2; 20]),
            state_root: OurH256([3; 32]),
            receipts_root: OurH256([4; 32]),
            logs_bloom: bellatrix::LogsBloom::try_from(vec![5u8; preset::BYTES_PER_LOGS_BLOOM])
                .unwrap(),
            prev_randao: OurH256([6; 32]),
            block_number: 7,
            gas_limit: 8,
            gas_used: 9,
            timestamp: 10,
            extra_data: bellatrix::ExtraData::try_from(vec![11, 12]).unwrap(),
            base_fee_per_gas: U256::from(13u64),
            block_hash: OurH256([14; 32]),
            transactions: transactions.try_into().unwrap(),
            withdrawals: vec![withdrawal(15), withdrawal(16)].try_into().unwrap(),
            blob_gas_used: 17,
            excess_blob_gas: 18,
        }
    }

    fn gloas_payload(block_access_list: Vec<u8>) -> gloas::ExecutionPayload {
        let deneb = deneb_payload();
        gloas::ExecutionPayload {
            parent_hash: deneb.parent_hash,
            fee_recipient: deneb.fee_recipient,
            state_root: deneb.state_root,
            receipts_root: deneb.receipts_root,
            logs_bloom: deneb.logs_bloom,
            prev_randao: deneb.prev_randao,
            block_number: deneb.block_number,
            gas_limit: deneb.gas_limit,
            gas_used: deneb.gas_used,
            timestamp: deneb.timestamp,
            extra_data: deneb.extra_data,
            base_fee_per_gas: deneb.base_fee_per_gas,
            block_hash: deneb.block_hash,
            transactions: vec![
                gloas::Transaction::from(transaction_bytes(1)),
                gloas::Transaction::from(transaction_bytes(2)),
            ]
            .into(),
            withdrawals: deneb.withdrawals.iter().cloned().collect::<Vec<_>>().into(),
            blob_gas_used: deneb.blob_gas_used,
            excess_blob_gas: deneb.excess_blob_gas,
            block_access_list: block_access_list.into(),
            slot_number: 19,
        }
    }

    /// The typed payload must be exactly what ethrex parses from the JSON the
    /// HTTP transport sends. ethrex's payload keeps its fields private, so
    /// the two are compared through its own serializer.
    #[test]
    fn a_typed_deneb_payload_matches_what_ethrex_parses_from_the_wire() {
        let payload = deneb_payload();
        let wire = serde_json::to_value(ExecutionPayloadV3(&payload)).unwrap();
        let parsed = ExecutionPayload::deserialize(&wire).expect("ethrex reads the wire shape");

        let typed = typed_payload(&PayloadFields::from(&payload), None).expect("representable");

        assert_eq!(
            serde_json::to_value(&typed).unwrap(),
            serde_json::to_value(&parsed).unwrap()
        );
    }

    #[test]
    fn a_typed_gloas_payload_matches_what_ethrex_parses_from_the_wire() {
        // `0xc0` is the RLP of an empty list: an empty but well-formed BAL.
        let payload = gloas_payload(vec![0xc0]);
        let wire = serde_json::to_value(ExecutionPayloadV4(&payload)).unwrap();
        let parsed = ExecutionPayload::deserialize(&wire).expect("ethrex reads the wire shape");

        let bal = decode_block_access_list(payload.block_access_list.as_ref());
        assert!(bal.is_some());
        let typed = typed_payload(&PayloadFields::from(&payload), bal).expect("representable");

        assert_eq!(
            serde_json::to_value(&typed).unwrap(),
            serde_json::to_value(&parsed).unwrap()
        );
    }

    #[test]
    fn the_claimed_block_hash_survives_the_conversion() {
        let payload = deneb_payload();
        let typed = typed_payload(&PayloadFields::from(&payload), None).unwrap();
        assert_eq!(typed.block_hash, H256([14; 32]));
    }

    #[test]
    fn an_undecodable_transaction_makes_the_payload_unrepresentable() {
        let mut payload = deneb_payload();
        payload.transactions = vec![bellatrix::Transaction::try_from(vec![0xff, 0x00]).unwrap()]
            .try_into()
            .unwrap();
        assert!(typed_payload(&PayloadFields::from(&payload), None).is_none());
    }

    #[test]
    fn a_base_fee_past_u64_makes_the_payload_unrepresentable() {
        let mut payload = deneb_payload();
        payload.base_fee_per_gas = U256::from_u128(u128::from(u64::MAX) + 1);
        assert!(typed_payload(&PayloadFields::from(&payload), None).is_none());
    }

    #[test]
    fn uint256_converts_up_to_u64_max() {
        assert_eq!(uint256_to_u64(&U256::from(0u64)), Some(0));
        assert_eq!(uint256_to_u64(&U256::from(u64::MAX)), Some(u64::MAX));
        assert_eq!(
            uint256_to_u64(&U256::from_u128(u128::from(u64::MAX) + 1)),
            None
        );
    }

    #[test]
    fn empty_or_malformed_block_access_lists_do_not_decode() {
        assert!(decode_block_access_list(&[]).is_none());
        assert!(decode_block_access_list(&[0xff, 0x01]).is_none());
        assert!(decode_block_access_list(&[0xc0]).is_some());
    }

    #[test]
    fn handler_errors_keep_their_wire_codes() {
        let unsupported = rpc_error(RpcErr::UnsupportedFork("Amsterdam".into()));
        assert!(
            matches!(unsupported, EngineError::Rpc { code: -38005, .. }),
            "{unsupported:?}"
        );

        let too_deep = rpc_error(RpcErr::TooDeepReorg("64 blocks".into()));
        assert!(
            matches!(too_deep, EngineError::Rpc { code: -38006, .. }),
            "{too_deep:?}"
        );
    }

    #[test]
    fn a_payload_id_is_its_eight_bytes_big_endian() {
        assert_eq!(payload_id_u64(PayloadId([0, 0, 0, 0, 0, 0, 1, 2])), 0x0102);
    }
}
