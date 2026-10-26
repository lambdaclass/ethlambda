//! Checks on a builder's bid before it may stand against the local payload.
//!
//! Everything that can be checked without the payload itself. The header
//! fields the state transition checks (parent hash, prev_randao, timestamp,
//! withdrawals, blob count) are checked here too, before
//! `assemble_blinded_block` repeats them as a backstop, so a refusal has a
//! reason to count and costs no state transition. What is left unchecked
//! (the payload's execution validity, its block hash and the fields only an
//! execution client could verify) is trusted to the relay, as every client
//! does: the payload is revealed only after the proposer signs.

use ethlambda_state_transition::beacon::block_production::PayloadInputs;
use ethlambda_state_transition::beacon::bls;
use ethlambda_state_transition::beacon::gossip::execution_payload_bid::is_gas_limit_target_compatible;
use ethlambda_types::beacon::builder::SignedBuilderBid;
use ethlambda_types::beacon::containers::capella;
use ethlambda_types::beacon::primitives::{HashTreeRoot as _, Version};
use ethlambda_types::beacon::signing::{compute_builder_domain, compute_signing_root};

use crate::beacon::bid_selection::wei_u128;

/// EIP-4844's blob gas per blob.
pub(crate) const GAS_PER_BLOB: u64 = 1 << 17;

/// What a bid is checked against, all from the proposal state and the
/// proposer's registration.
pub(crate) struct BidContext<'a> {
    pub(crate) genesis_fork_version: Version,
    pub(crate) inputs: &'a PayloadInputs,
    /// The block number of the payload the block builds on.
    pub(crate) parent_block_number: u64,
    /// The gas limit of the payload the block builds on.
    pub(crate) parent_gas_limit: u64,
    /// The gas limit the proposer registered.
    pub(crate) target_gas_limit: u64,
    pub(crate) max_blobs: u64,
}

/// Why a bid was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rejection {
    ZeroValue,
    ParentHash,
    PrevRandao,
    Timestamp,
    BlockNumber,
    Withdrawals,
    TooManyBlobs,
    BlobGas,
    GasLimit,
    Signature,
}

impl Rejection {
    /// The metric label.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::ZeroValue => "zero_value",
            Self::ParentHash => "parent_hash",
            Self::PrevRandao => "prev_randao",
            Self::Timestamp => "timestamp",
            Self::BlockNumber => "block_number",
            Self::Withdrawals => "withdrawals",
            Self::TooManyBlobs => "too_many_blobs",
            Self::BlobGas => "blob_gas",
            Self::GasLimit => "gas_limit",
            Self::Signature => "signature",
        }
    }
}

/// Whether `bid` is acceptable for the proposal `context` describes.
/// Cheap checks first; the signature, the one that costs a pairing, last.
///
/// The bid's fork label is not checked here: an electra bid at a fulu slot is
/// accepted on purpose (the containers are identical, so a lagging relay's bid
/// stays usable), and `BuilderClient` already refuses every other fork.
pub(crate) fn validate(bid: &SignedBuilderBid, context: &BidContext) -> Result<(), Rejection> {
    let message = &bid.message;
    let header = &message.header;
    if wei_u128(&message.value) == 0 {
        return Err(Rejection::ZeroValue);
    }
    if header.parent_hash != context.inputs.parent_hash {
        return Err(Rejection::ParentHash);
    }
    if header.prev_randao != context.inputs.prev_randao {
        return Err(Rejection::PrevRandao);
    }
    if header.timestamp != context.inputs.timestamp {
        return Err(Rejection::Timestamp);
    }
    // Against the parent's number rather than the local payload's, unlike
    // Lighthouse: the parent is always known, even when the local build failed.
    if context.parent_block_number.checked_add(1) != Some(header.block_number) {
        return Err(Rejection::BlockNumber);
    }
    let withdrawals: capella::Withdrawals = context
        .inputs
        .withdrawals
        .clone()
        .try_into()
        .map_err(|_| Rejection::Withdrawals)?;
    if header.withdrawals_root != withdrawals.hash_tree_root() {
        return Err(Rejection::Withdrawals);
    }
    let blobs = message.blob_kzg_commitments.len() as u64;
    if blobs > context.max_blobs {
        return Err(Rejection::TooManyBlobs);
    }
    if header.blob_gas_used != blobs * GAS_PER_BLOB {
        return Err(Rejection::BlobGas);
    }
    if !is_gas_limit_target_compatible(
        context.parent_gas_limit,
        header.gas_limit,
        context.target_gas_limit,
    ) {
        return Err(Rejection::GasLimit);
    }
    let domain = compute_builder_domain(context.genesis_fork_version);
    let root = compute_signing_root(message.hash_tree_root(), domain);
    if !bls::verify(&message.pubkey, root, &bid.signature) {
        return Err(Rejection::Signature);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ethlambda_types::beacon::builder::BuilderBid;
    use ethlambda_types::beacon::containers::capella::Withdrawal;
    use ethlambda_types::beacon::containers::deneb::ExecutionPayloadHeader;
    use ethlambda_types::beacon::containers::electra::{self, ExecutionRequests};
    use ethlambda_types::beacon::primitives::{
        BlsPubkey, Bytes32, ExecutionAddress, ExecutionBlockHash, KzgCommitment, Uint256,
    };

    use ethlambda_state_transition::beacon::helpers::test_state::secret_key_for;

    use super::*;
    use crate::beacon::builder_client::mock_relay::signed_bid;

    const GENESIS_FORK_VERSION: Version = [0x10, 0x00, 0x00, 0x38];
    const PARENT_BLOCK_NUMBER: u64 = 99;
    const PARENT_GAS_LIMIT: u64 = 30_000_000;
    const TARGET_GAS_LIMIT: u64 = 40_000_000;
    /// Lighthouse's `expected_gas_limit(30M, 40M)`: one adjustment step up.
    const NEXT_GAS_LIMIT: u64 = 30_029_295;

    fn inputs() -> PayloadInputs {
        PayloadInputs {
            timestamp: 1_700_000_012,
            prev_randao: Bytes32::repeat_byte(2),
            withdrawals: vec![Withdrawal {
                index: 1,
                validator_index: 2,
                address: ExecutionAddress::repeat_byte(4),
                amount: 5,
            }],
            parent_hash: ExecutionBlockHash::repeat_byte(3),
        }
    }

    fn context(inputs: &PayloadInputs) -> BidContext<'_> {
        BidContext {
            genesis_fork_version: GENESIS_FORK_VERSION,
            inputs,
            parent_block_number: PARENT_BLOCK_NUMBER,
            parent_gas_limit: PARENT_GAS_LIMIT,
            target_gas_limit: TARGET_GAS_LIMIT,
            max_blobs: 9,
        }
    }

    /// A one-blob bid that passes every check against `inputs()`, with `edit`
    /// applied before it is signed.
    fn bid(edit: impl FnOnce(&mut BuilderBid)) -> SignedBuilderBid {
        let inputs = inputs();
        let withdrawals: capella::Withdrawals = inputs.withdrawals.clone().try_into().unwrap();
        let mut header =
            ExecutionPayloadHeader::from(&electra::BeaconBlockBody::empty().execution_payload);
        header.parent_hash = inputs.parent_hash;
        header.prev_randao = inputs.prev_randao;
        header.timestamp = inputs.timestamp;
        header.block_number = PARENT_BLOCK_NUMBER + 1;
        header.withdrawals_root = withdrawals.hash_tree_root();
        header.gas_limit = NEXT_GAS_LIMIT;
        header.blob_gas_used = GAS_PER_BLOB;
        let mut message = BuilderBid {
            header,
            blob_kzg_commitments: vec![KzgCommitment::default()].try_into().unwrap(),
            execution_requests: ExecutionRequests::default(),
            value: Uint256::from(1_000_000_000u64),
            pubkey: BlsPubkey([0; 48]),
        };
        edit(&mut message);
        signed_bid(message, GENESIS_FORK_VERSION)
    }

    fn rejection(bid: &SignedBuilderBid) -> Option<Rejection> {
        validate(bid, &context(&inputs())).err()
    }

    #[test]
    fn a_bid_that_matches_the_proposal_is_accepted() {
        assert_eq!(rejection(&bid(|_| {})), None);
    }

    #[test]
    fn each_check_refuses_its_own_field() {
        type Edit = fn(&mut BuilderBid);
        let cases: [(Rejection, Edit); 9] = [
            (Rejection::ZeroValue, |bid| bid.value = Uint256::from(0u64)),
            (Rejection::ParentHash, |bid| {
                bid.header.parent_hash = ExecutionBlockHash::repeat_byte(9)
            }),
            (Rejection::PrevRandao, |bid| {
                bid.header.prev_randao = Bytes32::repeat_byte(9)
            }),
            (Rejection::Timestamp, |bid| bid.header.timestamp += 1),
            (Rejection::BlockNumber, |bid| bid.header.block_number += 1),
            (Rejection::Withdrawals, |bid| {
                bid.header.withdrawals_root = Bytes32::repeat_byte(9)
            }),
            (Rejection::TooManyBlobs, |bid| {
                bid.blob_kzg_commitments = vec![KzgCommitment::default(); 10].try_into().unwrap();
                bid.header.blob_gas_used = 10 * GAS_PER_BLOB;
            }),
            (Rejection::BlobGas, |bid| bid.header.blob_gas_used = 0),
            (Rejection::GasLimit, |bid| {
                bid.header.gas_limit = TARGET_GAS_LIMIT
            }),
        ];
        for (expected, edit) in cases {
            assert_eq!(rejection(&bid(edit)), Some(expected), "{expected:?}");
        }
    }

    #[test]
    fn a_block_number_that_overflows_is_refused() {
        let inputs = inputs();
        let mut context = context(&inputs);
        context.parent_block_number = u64::MAX;
        let bid = bid(|bid| bid.header.block_number = 0);
        assert_eq!(validate(&bid, &context), Err(Rejection::BlockNumber));
    }

    #[test]
    fn a_bid_changed_after_signing_is_refused() {
        let mut forged = bid(|_| {});
        forged.message.value = Uint256::from(2_000_000_000u64);
        assert_eq!(rejection(&forged), Some(Rejection::Signature));
    }

    #[test]
    fn a_bid_signed_by_a_key_other_than_the_one_it_names_is_refused() {
        let mut forged = bid(|_| {});
        // The signature is the relay's, the message names another key.
        forged.message.pubkey = BlsPubkey(secret_key_for(7).sk_to_pk().to_bytes());
        assert_eq!(rejection(&forged), Some(Rejection::Signature));
    }

    #[test]
    fn a_bid_signed_under_another_genesis_fork_version_is_refused() {
        let message = bid(|_| {}).message;
        let wrong = signed_bid(message, [0x99, 0x00, 0x00, 0x99]);
        assert_eq!(rejection(&wrong), Some(Rejection::Signature));
    }

    /// The gloas gossip predicate this reuses agrees with Lighthouse's
    /// `expected_gas_limit` on its own test vectors.
    #[test]
    fn the_gas_limit_rule_matches_lighthouses_vectors() {
        let vectors = [
            (30_000_000, 30_000_000, 30_000_000),
            (30_000_000, 40_000_000, 30_029_295),
            (30_029_295, 40_000_000, 30_058_619),
            (30_058_619, 30_000_000, 30_029_266),
        ];
        for (parent, target, expected) in vectors {
            assert!(is_gas_limit_target_compatible(parent, expected, target));
            assert!(!is_gas_limit_target_compatible(
                parent,
                expected + 1,
                target
            ));
        }
    }
}
