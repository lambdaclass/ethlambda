//! The execution block hash an execution payload claims, checked against the
//! header rebuilt from the payload's own fields.
//!
//! A payload carries its `block_hash` next to the fields that hash is taken
//! over, so a node can recompute it without an execution client: the header is
//! the payload's fields plus the transactions, withdrawals and requests tries,
//! RLP-encoded and keccak-hashed. The Engine API answers a mismatch with
//! `INVALID` and a null `latestValidHash` (execution-apis `shanghai.md`), which
//! is indistinguishable from a payload that executed badly and whose last valid
//! ancestor is unknown. Catching the structural case here keeps such a payload
//! from ever reaching fork choice. It is a rule stricter than the consensus
//! specification's gossip rules; see `docs/spec_deviations.md`.
//!
//! The header's shape per fork:
//!
//! | fork      | adds to the header                                        |
//! |-----------|-----------------------------------------------------------|
//! | bellatrix | the London fields, with `base_fee_per_gas`                |
//! | capella   | `withdrawals_root`                                        |
//! | deneb     | `blob_gas_used`, `excess_blob_gas`, `parent_beacon_block_root` |
//! | electra   | `requests_hash` (fulu is the same)                        |
//! | gloas     | `block_access_list_hash`, `slot_number`                   |
//!
//! Fields the execution layer fixes after the merge are constants here: no
//! ommers, difficulty zero, a zero nonce, `prev_randao` in the mix hash slot.
//! The header is encoded here rather than through ethrex's `BlockHeader`,
//! which holds `base_fee_per_gas` as a `u64` where the payload has 256 bits.

use ethlambda_state_transition::beacon::gossip::{Outcome, RejectReason};
use ethlambda_state_transition::beacon::stf::{electra, gloas as gloas_stf};
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::containers::{SignedBeaconBlock, capella, gloas};
use ethlambda_types::beacon::primitives::Root;
use ethrex_common::types::requests::{EncodedRequests, compute_requests_hash};
use ethrex_common::types::{Withdrawal, compute_withdrawals_root};
use ethrex_common::{Address, Bloom, Bytes, H256, NativeCrypto, U256};
use ethrex_rlp::encode::RLPEncode;
use ethrex_rlp::structs::Encoder;
use ethrex_trie::Trie;
use tracing::warn;

use crate::metrics;

/// `keccak256(rlp([]))`: the ommers hash of every post-merge block.
const EMPTY_OMMERS_HASH: [u8; 32] = [
    0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a, 0xab, 0x85, 0xb5, 0x67, 0xb6, 0xcc, 0xd4, 0x1a,
    0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13, 0xf0, 0xa1, 0x42, 0xfd, 0x40, 0xd4, 0x93, 0x47,
];

/// The hash the payload claims against the one its fields give.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashMismatch {
    pub claimed: [u8; 32],
    pub computed: [u8; 32],
}

/// What a payload and its surroundings supply to the header, whatever the fork.
struct Fields<'a> {
    parent_hash: [u8; 32],
    fee_recipient: [u8; 20],
    state_root: [u8; 32],
    receipts_root: [u8; 32],
    logs_bloom: &'a [u8],
    prev_randao: [u8; 32],
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: &'a [u8],
    /// 32 little-endian bytes, as SSZ carries it.
    base_fee_per_gas: [u8; 32],
    claimed_hash: [u8; 32],
    transactions: Vec<&'a [u8]>,
    /// `None` before capella.
    withdrawals: Option<&'a [capella::Withdrawal]>,
    /// `None` before deneb.
    blob_gas: Option<(u64, u64)>,
    /// `None` before deneb.
    parent_beacon_block_root: Option<[u8; 32]>,
    /// The Engine API's request list; `None` before electra.
    requests: Option<Vec<Vec<u8>>>,
    /// The payload's block access list bytes and slot number; `None` before gloas.
    amsterdam: Option<(&'a [u8], u64)>,
}

impl Fields<'_> {
    /// `keccak256(rlp(header))`.
    fn computed_hash(&self) -> [u8; 32] {
        // The trie roots are over opaque bytes: a transaction is already
        // `type || rlp(tx)` on the wire, so it is never decoded.
        let transactions = self
            .transactions
            .iter()
            .enumerate()
            .map(|(index, tx)| (index.encode_to_vec(), tx.to_vec()));
        let transactions_root = Trie::compute_hash_from_unsorted_iter(transactions, &NativeCrypto);
        let withdrawals_root = self.withdrawals.map(|withdrawals| {
            let withdrawals: Vec<Withdrawal> = withdrawals
                .iter()
                .map(|withdrawal| Withdrawal {
                    index: withdrawal.index,
                    validator_index: withdrawal.validator_index,
                    address: Address::from(withdrawal.address.0),
                    amount: withdrawal.amount,
                })
                .collect();
            compute_withdrawals_root(&withdrawals, &NativeCrypto)
        });
        let requests_hash = self.requests.as_ref().map(|requests| {
            let requests: Vec<EncodedRequests> = requests
                .iter()
                .map(|request| EncodedRequests(Bytes::copy_from_slice(request)))
                .collect();
            compute_requests_hash(&requests)
        });
        // EIP-7928: the header commits to the keccak of the RLP bytes the
        // payload carries, whatever they decode to.
        let block_access_list_hash = self
            .amsterdam
            .map(|(bal, _)| H256(ethrex_crypto_keccak(bal)));
        let slot_number = self.amsterdam.map(|(_, slot)| slot);
        let base_fee_per_gas = U256::from_little_endian(&self.base_fee_per_gas);

        let mut buf = Vec::with_capacity(700);
        Encoder::new(&mut buf)
            .encode_field(&H256(self.parent_hash))
            .encode_field(&H256(EMPTY_OMMERS_HASH))
            .encode_field(&Address::from(self.fee_recipient))
            .encode_field(&H256(self.state_root))
            .encode_field(&transactions_root)
            .encode_field(&H256(self.receipts_root))
            .encode_field(&Bloom::from_slice(self.logs_bloom))
            .encode_field(&U256::zero())
            .encode_field(&self.block_number)
            .encode_field(&self.gas_limit)
            .encode_field(&self.gas_used)
            .encode_field(&self.timestamp)
            .encode_field(&Bytes::copy_from_slice(self.extra_data))
            .encode_field(&H256(self.prev_randao))
            .encode_field(&[0u8; 8])
            .encode_field(&base_fee_per_gas)
            .encode_optional_field(&withdrawals_root)
            .encode_optional_field(&self.blob_gas.map(|(used, _)| used))
            .encode_optional_field(&self.blob_gas.map(|(_, excess)| excess))
            .encode_optional_field(&self.parent_beacon_block_root.map(H256))
            .encode_optional_field(&requests_hash)
            .encode_optional_field(&block_access_list_hash)
            .encode_optional_field(&slot_number)
            .finish();
        ethrex_crypto_keccak(&buf)
    }

    fn verify(&self) -> Result<(), HashMismatch> {
        let computed = self.computed_hash();
        if computed == self.claimed_hash {
            Ok(())
        } else {
            Err(HashMismatch {
                claimed: self.claimed_hash,
                computed,
            })
        }
    }
}

fn ethrex_crypto_keccak(data: &[u8]) -> [u8; 32] {
    ethrex_common::utils::keccak(data).0
}

/// The block's payload hash against its header, for every fork that carries
/// the payload in the block body.
///
/// A block before bellatrix, a bellatrix block from before the merge (its
/// payload is the empty default), and a gloas block (its payload arrives in a
/// separate envelope) have nothing to check.
pub fn verify_block(block: &SignedBeaconBlock) -> Result<(), HashMismatch> {
    match block {
        SignedBeaconBlock::Bellatrix(block) => {
            let payload = &block.message.body.execution_payload;
            if payload.block_hash.0 == [0; 32] && payload.parent_hash.0 == [0; 32] {
                return Ok(());
            }
            Fields {
                parent_hash: payload.parent_hash.0,
                fee_recipient: payload.fee_recipient.0,
                state_root: payload.state_root.0,
                receipts_root: payload.receipts_root.0,
                logs_bloom: payload.logs_bloom.as_ref(),
                prev_randao: payload.prev_randao.0,
                block_number: payload.block_number,
                gas_limit: payload.gas_limit,
                gas_used: payload.gas_used,
                timestamp: payload.timestamp,
                extra_data: payload.extra_data.as_ref(),
                base_fee_per_gas: payload.base_fee_per_gas.0,
                claimed_hash: payload.block_hash.0,
                transactions: payload.transactions.iter().map(|tx| &tx[..]).collect(),
                withdrawals: None,
                blob_gas: None,
                parent_beacon_block_root: None,
                requests: None,
                amsterdam: None,
            }
            .verify()
        }
        SignedBeaconBlock::Capella(block) => {
            let payload = &block.message.body.execution_payload;
            Fields {
                parent_hash: payload.parent_hash.0,
                fee_recipient: payload.fee_recipient.0,
                state_root: payload.state_root.0,
                receipts_root: payload.receipts_root.0,
                logs_bloom: payload.logs_bloom.as_ref(),
                prev_randao: payload.prev_randao.0,
                block_number: payload.block_number,
                gas_limit: payload.gas_limit,
                gas_used: payload.gas_used,
                timestamp: payload.timestamp,
                extra_data: payload.extra_data.as_ref(),
                base_fee_per_gas: payload.base_fee_per_gas.0,
                claimed_hash: payload.block_hash.0,
                transactions: payload.transactions.iter().map(|tx| &tx[..]).collect(),
                withdrawals: Some(payload.withdrawals.as_ref()),
                blob_gas: None,
                parent_beacon_block_root: None,
                requests: None,
                amsterdam: None,
            }
            .verify()
        }
        // Deneb, and electra and fulu on top of it: one payload container,
        // with the requests list the only addition.
        SignedBeaconBlock::Deneb(_)
        | SignedBeaconBlock::Electra(_)
        | SignedBeaconBlock::Fulu(_) => {
            let parent_root = match block {
                SignedBeaconBlock::Deneb(block) => block.message.parent_root.0,
                SignedBeaconBlock::Electra(block) | SignedBeaconBlock::Fulu(block) => {
                    block.message.parent_root.0
                }
                _ => unreachable!("narrowed by the outer match"),
            };
            let (payload, requests) = match block {
                SignedBeaconBlock::Deneb(block) => (&block.message.body.execution_payload, None),
                SignedBeaconBlock::Electra(block) | SignedBeaconBlock::Fulu(block) => (
                    &block.message.body.execution_payload,
                    Some(electra::get_execution_requests_list(
                        &block.message.body.execution_requests,
                    )),
                ),
                _ => unreachable!("narrowed by the outer match"),
            };
            Fields {
                parent_hash: payload.parent_hash.0,
                fee_recipient: payload.fee_recipient.0,
                state_root: payload.state_root.0,
                receipts_root: payload.receipts_root.0,
                logs_bloom: payload.logs_bloom.as_ref(),
                prev_randao: payload.prev_randao.0,
                block_number: payload.block_number,
                gas_limit: payload.gas_limit,
                gas_used: payload.gas_used,
                timestamp: payload.timestamp,
                extra_data: payload.extra_data.as_ref(),
                base_fee_per_gas: payload.base_fee_per_gas.0,
                claimed_hash: payload.block_hash.0,
                transactions: payload.transactions.iter().map(|tx| &tx[..]).collect(),
                withdrawals: Some(payload.withdrawals.as_ref()),
                blob_gas: Some((payload.blob_gas_used, payload.excess_blob_gas)),
                parent_beacon_block_root: Some(parent_root),
                requests,
                amsterdam: None,
            }
            .verify()
        }
        SignedBeaconBlock::Phase0(_)
        | SignedBeaconBlock::Altair(_)
        | SignedBeaconBlock::Gloas(_)
        | SignedBeaconBlock::Lean(_) => Ok(()),
    }
}

/// A gloas envelope's payload hash against its header.
pub fn verify_envelope(
    envelope: &gloas::SignedExecutionPayloadEnvelope,
) -> Result<(), HashMismatch> {
    let message = &envelope.message;
    let payload = &message.payload;
    Fields {
        parent_hash: payload.parent_hash.0,
        fee_recipient: payload.fee_recipient.0,
        state_root: payload.state_root.0,
        receipts_root: payload.receipts_root.0,
        logs_bloom: payload.logs_bloom.as_ref(),
        prev_randao: payload.prev_randao.0,
        block_number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: payload.extra_data.as_ref(),
        base_fee_per_gas: payload.base_fee_per_gas.0,
        claimed_hash: payload.block_hash.0,
        transactions: payload.transactions.iter().map(|tx| &tx[..]).collect(),
        withdrawals: Some(payload.withdrawals.as_ref()),
        blob_gas: Some((payload.blob_gas_used, payload.excess_blob_gas)),
        parent_beacon_block_root: Some(message.parent_beacon_block_root.0),
        requests: Some(gloas_stf::get_execution_requests_list(
            &message.execution_requests,
        )),
        amsterdam: Some((payload.block_access_list.as_ref(), payload.slot_number)),
    }
    .verify()
}

/// `envelope` with its payload's `block_hash` set to the header's, for tests
/// that build a structurally valid envelope out of arbitrary fields.
#[cfg(test)]
pub(crate) fn seal_envelope(
    mut envelope: gloas::SignedExecutionPayloadEnvelope,
) -> gloas::SignedExecutionPayloadEnvelope {
    if let Err(mismatch) = verify_envelope(&envelope) {
        envelope.message.payload.block_hash = mismatch.computed.into();
    }
    envelope
}

/// [`verify_block`] as a gossip verdict: `Err(Reject)` on a mismatch, counted
/// and logged.
pub(crate) fn reject_block_on_mismatch(
    block: &SignedBeaconBlock,
    block_root: Root,
) -> Result<(), Outcome> {
    verify_block(block).map_err(|mismatch| refuse("block", block.slot(), block_root, mismatch))
}

/// [`verify_envelope`] as a verdict, shared by the gossip topic and the
/// fetched-envelope checks.
pub(crate) fn reject_envelope_on_mismatch(
    envelope: &gloas::SignedExecutionPayloadEnvelope,
) -> Result<(), Outcome> {
    verify_envelope(envelope).map_err(|mismatch| {
        refuse(
            "envelope",
            envelope.message.payload.slot_number,
            envelope.message.beacon_block_root,
            mismatch,
        )
    })
}

fn refuse(kind: &str, slot: u64, root: Root, mismatch: HashMismatch) -> Outcome {
    metrics::inc_beacon_payload_block_hash_mismatch(kind);
    warn!(
        kind,
        slot,
        root = %ShortRoot(&root.0),
        claimed = %ShortRoot(&mismatch.claimed),
        computed = %ShortRoot(&mismatch.computed),
        "Refusing an execution payload whose block hash is not its header's"
    );
    Outcome::Reject(RejectReason::PayloadBlockHashMismatch)
}

#[cfg(test)]
mod tests;
