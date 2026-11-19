//! The execution block hash an execution payload claims, checked against the
//! header rebuilt from the payload's own fields.
//!
//! A payload carries its `block_hash` next to the fields that hash is taken
//! over, so a node can recompute it without an execution client: the header is
//! the payload's fields plus the transactions, withdrawals and requests tries,
//! RLP-encoded and keccak-hashed.
//!
//! The consensus specification has no such gossip rule, and the Engine API
//! already requires the execution client to validate `blockHash` on every
//! `engine_newPayload`, even while syncing (execution-apis `paris.md`). While
//! an import waits for that answer, this finds nothing the execution client
//! would not. What it buys is a gossip block refused before it is imported:
//! once a pre-gloas payload is applied to fork choice before the execution
//! client answers (lambdaclass/ethlambda#773), a block caught here is one that
//! never has to be reverted. See `docs/spec_deviations.md`.
//!
//! Where it runs, and what it answers:
//!
//! - A pre-gloas `beacon_block` from gossip, once its stateful checks answered
//!   `Accept` ([`block_verdict`]). That is the one outcome that says the
//!   proposer's signature verified, so no unsigned message makes this node
//!   build a transaction trie. A mismatch is `IGNORE`, not `REJECT`: other
//!   clients have no such rule and forward the block, and a `REJECT` would
//!   score every honest peer that relayed it.
//! - A gloas envelope, from gossip or fetched, once its checks answered
//!   `Accept` ([`envelope_verdict`]): counted and logged, never refused, until
//!   the Amsterdam header is final.
//! - Nothing else. A block fetched by range or root, and a gossip block
//!   forwarded under `Queue` or `Ignore(Overloaded)`, reach the chain actor
//!   unhashed; the execution client still checks them.
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

use ethlambda_state_transition::beacon::gossip::{IgnoreReason, Outcome};
use ethlambda_state_transition::beacon::stf::{electra, gloas as gloas_stf};
use ethlambda_types::ShortRoot;
use ethlambda_types::beacon::containers::{SignedBeaconBlock, bellatrix, capella, deneb, gloas};
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

impl<'a> Fields<'a> {
    /// The header fields of deneb's payload container, which electra and fulu
    /// reuse with the requests list as their only addition.
    fn deneb(
        payload: &'a deneb::ExecutionPayload,
        parent_root: Root,
        requests: Option<Vec<Vec<u8>>>,
    ) -> Self {
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
            parent_beacon_block_root: Some(parent_root.0),
            requests,
            amsterdam: None,
        }
    }

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
        let block_access_list_hash = self.amsterdam.map(|(bal, _)| H256(keccak256(bal)));
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
        keccak256(&buf)
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

fn keccak256(data: &[u8]) -> [u8; 32] {
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
            // The specification's `is_execution_enabled` asks the same of a
            // pre-merge block: its payload is the whole default container.
            if *payload == bellatrix::ExecutionPayload::default() {
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
        SignedBeaconBlock::Deneb(block) => {
            let message = &block.message;
            Fields::deneb(&message.body.execution_payload, message.parent_root, None).verify()
        }
        SignedBeaconBlock::Electra(block) | SignedBeaconBlock::Fulu(block) => {
            let message = &block.message;
            let requests = electra::get_execution_requests_list(&message.body.execution_requests);
            let payload = &message.body.execution_payload;
            Fields::deneb(payload, message.parent_root, Some(requests)).verify()
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

/// A gossip block's verdict, given the `outcome` its stateful checks answered.
///
/// Only an `Accept` is hashed: it is the one outcome that says the proposer's
/// signature verified, so only a proposer can make this node build the trie
/// or reach the `warn!`. A mismatch turns it into
/// `Ignore(PayloadBlockHashMismatch)`, which keeps the block from being
/// imported or relayed without scoring the peers that relayed it. Any other
/// outcome passes through unhashed.
pub(crate) fn block_verdict(
    outcome: Outcome,
    block: &SignedBeaconBlock,
    block_root: Root,
) -> Outcome {
    if outcome != Outcome::Accept {
        return outcome;
    }
    let Err(mismatch) = verify_block(block) else {
        return outcome;
    };
    metrics::inc_beacon_payload_block_hash_mismatch("block");
    let slot = block.slot();
    warn!(
        slot,
        block_root = %ShortRoot(&block_root.0),
        claimed = %ShortRoot(&mismatch.claimed),
        computed = %ShortRoot(&mismatch.computed),
        "Ignoring a gossip block whose payload block hash is not its header's"
    );
    Outcome::Ignore(IgnoreReason::PayloadBlockHashMismatch)
}

/// A gloas envelope's verdict, given the `outcome` its checks answered: always
/// `outcome`, with an `Accept` whose payload hash is not its header's counted
/// and logged.
///
/// Not refused, unlike a pre-gloas block. The Amsterdam header (EIP-7928's
/// block access list hash, EIP-7843's slot number) is still moving between
/// devnets, and an envelope is judged here on gossip and on fetch alike, so a
/// header this build encodes wrongly would refuse every payload and leave the
/// node unable to follow the chain; a pre-gloas block refused on gossip still
/// comes back by root. The counter says whether the encoding agrees with the
/// chain until the header is final and this can refuse.
pub(crate) fn envelope_verdict(
    outcome: Outcome,
    envelope: &gloas::SignedExecutionPayloadEnvelope,
) -> Outcome {
    if outcome != Outcome::Accept {
        return outcome;
    }
    let _ = verify_envelope(envelope).inspect_err(|mismatch| {
        metrics::inc_beacon_payload_block_hash_mismatch("envelope");
        let slot = envelope.message.payload.slot_number;
        warn!(
            slot,
            block_root = %ShortRoot(&envelope.message.beacon_block_root.0),
            claimed = %ShortRoot(&mismatch.claimed),
            computed = %ShortRoot(&mismatch.computed),
            "An envelope's payload block hash is not its header's; not refused before the Amsterdam header is final"
        );
    });
    outcome
}

#[cfg(test)]
mod tests;
