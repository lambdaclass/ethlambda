//! Assembling an EIP-8453 block from the fork choice's proposal.
//!
//! The pieces a proposer needs beyond the engine's `get_ac_proposal`
//! ([`crate::beacon::eip8453_node::Eip8453Proposal`]): the pooled single
//! attestations aggregated into the body's `Attestation`s, keeping only those
//! `process_attestation` accepts on the block's pre-state
//! ([`pack_attestations`]), and the unsigned block with its post-state root
//! ([`assemble_block`]). The Beacon API's block production endpoint and the
//! in-process network test build on these; signing is the caller's.

use std::collections::BTreeMap;

use crate::beacon::config::Config;
use crate::beacon::containers::{BeaconState, SignedBeaconBlock, eip8453, gloas};
use crate::beacon::error::Result;
use crate::beacon::helpers::accessors::{
    ActiveBalanceCache, CommitteeCache, get_beacon_proposer_index,
};
use crate::beacon::helpers::eip8453::get_attestation_committee;
use crate::beacon::preset;
use crate::beacon::primitives::{BlsSignature, Epoch, Root, Slot};
use crate::beacon::stf::{self, ExecutionEngine, block::BlockProcessingOptions};

/// Aggregate single attestations into the body's `Attestation`s: one per
/// `(data, epoch)`, over the committees its attesters sit in, and keep the
/// ones `process_attestation` accepts on `state` (the block's pre-state,
/// advanced to its slot), in that order, up to `MAX_ATTESTATIONS_ELECTRA`.
pub fn pack_attestations<'a>(
    state: &BeaconState,
    pool: impl IntoIterator<Item = &'a eip8453::SingleAttestation>,
) -> Vec<eip8453::Attestation> {
    // (epoch, data) -> committee -> attester -> signature
    type Signers = BTreeMap<u64, BTreeMap<u64, BlsSignature>>;
    let mut groups: BTreeMap<(Epoch, [u8; 81]), (eip8453::AttestationData, Signers)> =
        BTreeMap::new();
    for attestation in pool {
        let key = (attestation.epoch, attestation_key(&attestation.data));
        let (_, signers) = groups
            .entry(key)
            .or_insert_with(|| (attestation.data, BTreeMap::new()));
        signers
            .entry(attestation.committee_index)
            .or_default()
            .insert(attestation.attester_index, attestation.signature);
    }
    let mut scratch = state.clone();
    let mut packed = Vec::new();
    for ((epoch, _), (data, signers)) in groups {
        let Some(attestation) = aggregate(state, epoch, data, &signers) else {
            continue;
        };
        if stf::eip8453::process_attestation(&mut scratch, &attestation).is_ok() {
            packed.push(attestation);
            if packed.len() == preset::MAX_ATTESTATIONS_ELECTRA {
                break;
            }
        }
    }
    packed
}

/// The SSZ bytes of `data`, a total order to group by.
fn attestation_key(data: &eip8453::AttestationData) -> [u8; 81] {
    let bytes = libssz::SszEncode::to_ssz(data);
    let mut key = [0u8; 81];
    key.copy_from_slice(&bytes[..81]);
    key
}

/// One `Attestation` of `data` for `epoch` from the attesters in `signers`,
/// by committee: `committee_bits` names their committees, `aggregation_bits`
/// marks them in the committees' concatenation.
fn aggregate(
    state: &BeaconState,
    epoch: Epoch,
    data: eip8453::AttestationData,
    signers: &BTreeMap<u64, BTreeMap<u64, BlsSignature>>,
) -> Option<eip8453::Attestation> {
    let mut committee_bits = eip8453::AttestationCommitteeBits::new();
    let mut bits = Vec::new();
    let mut signatures = Vec::new();
    for (&committee_index, attesters) in signers {
        let committee = get_attestation_committee(state, epoch, committee_index).ok()?;
        committee_bits.set(committee_index as usize, true).ok()?;
        for member in committee.iter() {
            match attesters.get(member) {
                Some(signature) => {
                    bits.push(true);
                    signatures.push(*signature);
                }
                None => bits.push(false),
            }
        }
    }
    if signatures.is_empty() {
        return None;
    }
    let mut aggregation_bits = eip8453::AggregationBits::with_length(bits.len());
    for (position, bit) in bits.into_iter().enumerate() {
        if bit {
            aggregation_bits.set(position, true).ok()?;
        }
    }
    Some(eip8453::Attestation {
        aggregation_bits,
        data,
        signature: crate::beacon::bls::aggregate(&signatures).ok()?,
        committee_bits,
        epoch,
    })
}

/// The unsigned EIP-8453 block at `slot` on `parent_root`, whose post-state
/// is `pre_state` (the parent's post-state) advanced to `slot` and run through
/// the block, and the post-state's root in `state_root`. Errors with the state
/// transition's own error when the body does not apply.
#[allow(clippy::too_many_arguments)]
pub fn assemble_block(
    pre_state: &BeaconState,
    parent_root: Root,
    slot: Slot,
    randao_reveal: BlsSignature,
    signed_execution_payload_bid: gloas::SignedExecutionPayloadBid,
    head_votes: Vec<eip8453::HeadVote>,
    head_vote_support: Vec<eip8453::HeadVoteSupportBits>,
    attestations: Vec<eip8453::Attestation>,
    config: &Config,
) -> Result<(eip8453::BeaconBlock, BeaconState)> {
    let mut state = pre_state.clone();
    if state.slot() < slot {
        stf::process_slots(&mut state, slot, config)?;
    }
    let mut body = eip8453::BeaconBlockBody::empty();
    body.randao_reveal = randao_reveal;
    body.signed_execution_payload_bid = signed_execution_payload_bid;
    body.head_votes = head_votes.into();
    body.head_vote_support = head_vote_support.into();
    body.attestations = attestations.into();
    body.sync_aggregate.sync_committee_signature =
        BlsSignature(crate::beacon::bls::G2_POINT_AT_INFINITY);
    let mut block = eip8453::BeaconBlock {
        slot,
        proposer_index: get_beacon_proposer_index(&state)?,
        parent_root,
        state_root: Root::ZERO,
        body,
    };
    let unsigned = SignedBeaconBlock::Eip8453(eip8453::SignedBeaconBlock {
        message: block.clone(),
        signature: BlsSignature::default(),
    });
    stf::block::process_block(
        &mut state,
        &unsigned,
        config,
        &ExecutionEngine::valid(),
        &CommitteeCache::default(),
        &ActiveBalanceCache::default(),
        BlockProcessingOptions::default(),
    )?;
    state.apply_pending_mutations();
    block.state_root = state.hash_tree_root();
    Ok((block, state))
}
