//! Assembling a self-built gloas block and the payload envelope that fulfills
//! it, per gloas `validator.md` ("Constructing the `BeaconBlockBody`") and
//! `builder.md` ("Constructing the `SignedExecutionPayloadBid`" and
//! "Constructing the `SignedExecutionPayloadEnvelope`").
//!
//! Gloas splits what fulu's [`super::block_production`] assembles in one piece:
//! the block commits to a bid, and the payload travels afterward in an
//! envelope. This node only ever builds for itself (`BUILDER_INDEX_SELF_BUILD`),
//! so the bid is its own: zero value, the G2 point at infinity for a
//! signature, and every field read off the payload its execution client built.
//! The proposer then owes the network the envelope (signed with its own key,
//! see `process_execution_payload_bid`'s self-build branch) and the data
//! columns of the blobs the bid commits to; [`assemble_gloas_block`] returns
//! the unsigned envelope next to the block.
//!
//! Everything the execution client supplies arrives already built. What this
//! module decides is what the consensus layer decides: which parent payload
//! the build extends ([`gloas_payload_inputs`]), which attestations and
//! payload attestations ride in the body, and the state root, which comes from
//! running the block through gloas's `process_block` on a copy of the state.

use std::collections::BTreeMap;

use super::block_production::{empty_sync_aggregate, pack_attestations};
use super::bls;
use super::config::Config;
use super::error::{Error, Result, verify};
use super::helpers::accessors::{
    CommitteeCache, get_beacon_proposer_index, get_current_epoch, get_randao_mix,
};
use super::helpers::gloas::{
    get_indexed_payload_attestation, get_ptc, gloas_state_ref, is_attestation_same_slot,
    is_valid_indexed_payload_attestation,
};
use super::stf;
use ethlambda_types::beacon::{
    constants,
    containers::{
        BeaconState,
        capella::Withdrawal,
        electra,
        gloas::{
            self, BeaconBlock, BeaconBlockBody, ExecutionPayload, ExecutionPayloadBid,
            ExecutionPayloadEnvelope, ExecutionRequests, PayloadAttestation,
            PayloadAttestationData, PayloadAttestationMessage, SignedExecutionPayloadBid,
        },
    },
    preset,
    primitives::{
        BlsSignature, Bytes32, ExecutionBlockHash, HashTreeRoot as _, KzgCommitment, Root, Slot,
        ValidatorIndex,
    },
};

/// What the execution client needs to build the payload for the slot `state`
/// has been advanced to: `PayloadAttributesV4`, less the fee recipient, plus
/// the execution block the build extends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GloasPayloadInputs {
    pub timestamp: u64,
    pub prev_randao: Bytes32,
    pub withdrawals: Vec<Withdrawal>,
    /// The execution block the payload must extend: the head of the
    /// `forkchoiceUpdated` that starts the build.
    pub head_block_hash: ExecutionBlockHash,
    /// `hash_tree_root(state.latest_block_header)`.
    pub parent_beacon_block_root: Root,
    pub slot_number: u64,
    pub target_gas_limit: u64,
}

/// The payload inputs for the block at `state`'s slot, from `prepare_execution_payload`
/// (gloas `validator.md`).
///
/// `build_on_full` is `should_build_on_full(store, head, current_slot)`: the
/// proposer builds on the parent's revealed payload, so the parent's requests
/// (`parent_requests`, empty when the parent is pre-gloas) are applied to a
/// copy of the state first, and the withdrawals are those of that copy. Else
/// the parent's payload is skipped and the withdrawals are the ones the state
/// already expects. The target gas limit is the parent bid's own (contract
/// decision: this node expresses no preference of its own).
pub fn gloas_payload_inputs(
    state: &BeaconState,
    build_on_full: bool,
    parent_requests: &ExecutionRequests,
    config: &Config,
) -> Result<GloasPayloadInputs> {
    let inner = gloas_state_ref(state, "gloas_payload_inputs")?;
    let parent_bid = &inner.latest_execution_payload_bid;
    let (withdrawals, head_block_hash) = if build_on_full {
        let mut applied = state.clone();
        stf::gloas::apply_parent_execution_payload(&mut applied, parent_requests, config)?;
        (
            stf::gloas::get_expected_withdrawals(&applied)?.withdrawals,
            parent_bid.block_hash,
        )
    } else {
        (
            inner.payload_expected_withdrawals.iter().cloned().collect(),
            parent_bid.parent_block_hash,
        )
    };
    Ok(GloasPayloadInputs {
        timestamp: stf::bellatrix::compute_timestamp_at_slot(state, state.slot(), config),
        prev_randao: get_randao_mix(state, get_current_epoch(state)),
        withdrawals,
        head_block_hash,
        parent_beacon_block_root: state.latest_block_header().hash_tree_root(),
        slot_number: state.slot(),
        target_gas_limit: parent_bid.gas_limit,
    })
}

/// `get_execution_requests` (gloas `validator.md`): the execution client's
/// EIP-7685 request list into gloas's five-kind `ExecutionRequests`.
///
/// The types must be strictly ascending and no element empty, which is
/// checked rather than trusted, since a list this node accepted would go into
/// a bid its peers then reject.
pub fn parse_gloas_execution_requests(list: &[Vec<u8>]) -> Result<ExecutionRequests> {
    let mut requests = ExecutionRequests::default();
    let mut previous_type: Option<u8> = None;
    for element in list {
        let (&request_type, data) = element
            .split_first()
            .ok_or(Error::SpecAssert("an execution request carries its type"))?;
        verify(!data.is_empty(), "an execution request is not empty")?;
        verify(
            previous_type.is_none_or(|previous| request_type > previous),
            "execution request types are strictly ascending",
        )?;
        previous_type = Some(request_type);
        let malformed = |_| Error::SpecAssert("an execution request list decodes as SSZ");
        match request_type {
            constants::DEPOSIT_REQUEST_TYPE => {
                requests.deposits = libssz::SszDecode::from_ssz_bytes(data).map_err(malformed)?;
            }
            constants::WITHDRAWAL_REQUEST_TYPE => {
                requests.withdrawals =
                    libssz::SszDecode::from_ssz_bytes(data).map_err(malformed)?;
            }
            constants::CONSOLIDATION_REQUEST_TYPE => {
                requests.consolidations =
                    libssz::SszDecode::from_ssz_bytes(data).map_err(malformed)?;
            }
            constants::BUILDER_DEPOSIT_REQUEST_TYPE => {
                requests.builder_deposits =
                    libssz::SszDecode::from_ssz_bytes(data).map_err(malformed)?;
            }
            constants::BUILDER_EXIT_REQUEST_TYPE => {
                requests.builder_exits =
                    libssz::SszDecode::from_ssz_bytes(data).map_err(malformed)?;
            }
            _ => return Err(Error::SpecAssert("a known execution request type")),
        }
    }
    Ok(requests)
}

/// Pick the attestations for a gloas block at `state`'s slot from the
/// electra-shaped pool `candidates`.
///
/// Everything [`pack_attestations`] enforces, plus gloas `process_attestation`'s
/// payload-availability rule: `data.index` is `0` or `1`, and `0` when the
/// vote is for the block of its own slot (`is_attestation_same_slot`), which
/// `get_attestation_participation_flag_indices` asserts. A vote failing that
/// would fail the whole block, so it is left out here.
pub fn pack_gloas_attestations(
    state: &BeaconState,
    candidates: Vec<electra::Attestation>,
) -> Vec<gloas::Attestation> {
    let includable = |attestation: &electra::Attestation| {
        let data = &attestation.data;
        data.index < 2
            && is_attestation_same_slot(state, data)
                .is_ok_and(|same_slot| !same_slot || data.index == 0)
    };
    pack_attestations(state, candidates.into_iter().filter(includable).collect())
        .iter()
        .map(gloas::Attestation::from)
        .collect()
}

/// The payload attestations for a block at `state`'s slot, aggregated from the
/// pool's `messages` (gloas `validator.md`, "Payload attestations").
///
/// Only the parent block's own slot is attested to: the votes must be for
/// `parent_root`, and the parent must sit exactly one slot before this block.
/// Votes sharing one `PayloadAttestationData` become one aggregate. Its bit
/// `i` is set for every position `i` of `get_ptc(state, parent_slot)` whose
/// validator has a vote on that data, and that vote's signature is aggregated
/// once per such position: a validator holding two seats sets two bits and
/// contributes twice, which is what `get_indexed_payload_attestation` followed
/// by `FastAggregateVerify` over the repeated key expects.
///
/// An aggregate that does not verify against `state` is dropped, since one bad
/// operation fails the whole block. At most `MAX_PAYLOAD_ATTESTATIONS` are
/// returned, the ones covering the most seats first.
pub fn pack_payload_attestations(
    state: &BeaconState,
    parent_root: Root,
    parent_slot: Slot,
    messages: Vec<PayloadAttestationMessage>,
    config: &Config,
) -> Vec<PayloadAttestation> {
    if parent_slot.checked_add(1) != Some(state.slot()) {
        return Vec::new();
    }
    let Ok(ptc) = get_ptc(state, parent_slot, config) else {
        return Vec::new();
    };

    // One entry per distinct data: the first signature each validator sent.
    let mut groups: BTreeMap<
        Root,
        (
            PayloadAttestationData,
            BTreeMap<ValidatorIndex, BlsSignature>,
        ),
    > = BTreeMap::new();
    for message in messages {
        if message.data.beacon_block_root != parent_root || message.data.slot != parent_slot {
            continue;
        }
        groups
            .entry(message.data.hash_tree_root())
            .or_insert_with(|| (message.data, BTreeMap::new()))
            .1
            .entry(message.validator_index)
            .or_insert(message.signature);
    }

    let mut packed: Vec<(usize, PayloadAttestation)> = groups
        .into_values()
        .filter_map(|(data, votes)| {
            let mut aggregation_bits = gloas::PayloadTimelinessCommitteeBits::default();
            let mut signatures = Vec::new();
            for (position, validator) in ptc.iter().enumerate() {
                if let Some(signature) = votes.get(validator) {
                    aggregation_bits.set(position, true).ok()?;
                    signatures.push(*signature);
                }
            }
            let seats = signatures.len();
            let attestation = PayloadAttestation {
                aggregation_bits,
                data,
                signature: bls::aggregate(&signatures).ok()?,
            };
            let indexed = get_indexed_payload_attestation(state, &attestation, config).ok()?;
            is_valid_indexed_payload_attestation(state, &indexed).then_some((seats, attestation))
        })
        .collect();
    packed.sort_by_key(|(seats, _)| std::cmp::Reverse(*seats));
    packed
        .into_iter()
        .map(|(_, attestation)| attestation)
        .take(preset::MAX_PAYLOAD_ATTESTATIONS as usize)
        .collect()
}

/// `get_data_column_sidecars` (gloas `builder.md`): the `NUMBER_OF_COLUMNS`
/// column sidecars of the blobs a payload carries, named by the block they
/// belong to rather than by a signed header and an inclusion proof.
///
/// `blobs` are the raw blobs and `cell_proofs` the execution client's
/// flattened cell proofs, `CELLS_PER_EXT_BLOB` per blob in blob order
/// (`BlobsBundleV2`). The cells are recomputed from the blobs, since the
/// bundle carries only proofs. Fails when the proof count does not match, or
/// a blob is not valid.
pub fn gloas_data_column_sidecars(
    beacon_block_root: Root,
    slot: Slot,
    blobs: &[Vec<u8>],
    cell_proofs: &[ethlambda_types::beacon::primitives::KzgProof],
) -> Result<Vec<gloas::DataColumnSidecar>> {
    verify(
        cell_proofs.len() == blobs.len() * preset::CELLS_PER_EXT_BLOB,
        "a blob carries CELLS_PER_EXT_BLOB cell proofs",
    )?;
    let per_blob_cells = blobs
        .iter()
        .map(|blob| super::kzg::compute_cells(blob))
        .collect::<Result<Vec<_>>>()?;

    (0..preset::NUMBER_OF_COLUMNS)
        .map(|column_index| {
            let mut column = Vec::with_capacity(blobs.len());
            let mut kzg_proofs = Vec::with_capacity(blobs.len());
            for (blob, cells) in per_blob_cells.iter().enumerate() {
                let cell = ethlambda_types::beacon::containers::fulu::Cell::try_from(
                    cells[column_index].to_bytes().to_vec(),
                )
                .map_err(|_| Error::SpecAssert("len(cell) == BYTES_PER_CELL"))?;
                column.push(cell);
                kzg_proofs.push(cell_proofs[blob * preset::CELLS_PER_EXT_BLOB + column_index]);
            }
            Ok(gloas::DataColumnSidecar {
                index: column_index as u64,
                column: column.into(),
                kzg_proofs: kzg_proofs.into(),
                slot,
                beacon_block_root,
            })
        })
        .collect()
}

/// What a gloas block body carries beyond what this module derives from the
/// state.
#[derive(Debug, Clone)]
pub struct GloasBlockInputs {
    pub randao_reveal: BlsSignature,
    pub graffiti: Bytes32,
    pub attestations: Vec<gloas::Attestation>,
    pub payload_attestations: Vec<PayloadAttestation>,
    /// The parent envelope's requests when building on its full payload and
    /// the parent is gloas; empty otherwise.
    pub parent_execution_requests: ExecutionRequests,
    /// The payload `engine_getPayloadV6` built, which the envelope reveals.
    pub execution_payload: ExecutionPayload,
    /// The blobs bundle's commitments, which the bid commits to.
    pub blob_kzg_commitments: Vec<KzgCommitment>,
    /// The payload's own requests, which the bid commits to by root and the
    /// envelope carries.
    pub execution_requests: ExecutionRequests,
}

/// A produced block and the unsigned envelope that reveals its payload.
#[derive(Debug, Clone)]
pub struct GloasProduced {
    pub block: BeaconBlock,
    pub envelope: ExecutionPayloadEnvelope,
}

/// The unsigned self-built block for the slot `state` has been advanced to, with
/// its state root computed, and the unsigned envelope for its payload.
///
/// The body votes the state's own `eth1_data`, carries no slashings, exits or
/// credential changes (this node pools none) and an empty sync aggregate. The
/// block is run through gloas's `process_block` on a copy of `state`, which
/// is also what rejects a body the network would, before anything is signed.
/// The envelope is then checked against that post-state with every condition
/// `verify_execution_payload_envelope` holds it to except the signature, so a
/// malformed build fails here and not on the network.
pub fn assemble_gloas_block(
    state: &BeaconState,
    inputs: GloasBlockInputs,
    config: &Config,
) -> Result<GloasProduced> {
    verify(
        matches!(state, BeaconState::Gloas(_)),
        "gloas block production runs on a gloas state",
    )?;
    let payload = &inputs.execution_payload;
    let bid = ExecutionPayloadBid {
        parent_block_hash: payload.parent_hash,
        parent_block_root: state.latest_block_header().hash_tree_root(),
        block_hash: payload.block_hash,
        prev_randao: payload.prev_randao,
        fee_recipient: payload.fee_recipient,
        gas_limit: payload.gas_limit,
        builder_index: constants::BUILDER_INDEX_SELF_BUILD,
        slot: state.slot(),
        value: 0,
        execution_payment: 0,
        blob_kzg_commitments: inputs.blob_kzg_commitments.into(),
        execution_requests_root: inputs.execution_requests.hash_tree_root(),
    };
    let body = BeaconBlockBody {
        randao_reveal: inputs.randao_reveal,
        eth1_data: state.eth1_data().clone(),
        graffiti: inputs.graffiti,
        attestations: inputs.attestations.into(),
        sync_aggregate: empty_sync_aggregate(),
        signed_execution_payload_bid: SignedExecutionPayloadBid {
            message: bid,
            signature: BlsSignature(bls::G2_POINT_AT_INFINITY),
        },
        payload_attestations: inputs.payload_attestations.into(),
        parent_execution_requests: inputs.parent_execution_requests,
        ..BeaconBlockBody::empty()
    };
    let mut block = BeaconBlock {
        slot: state.slot(),
        proposer_index: get_beacon_proposer_index(state)?,
        // `process_slots` filled the header's state root on the way out of
        // the parent's slot, so this is the parent block's root.
        parent_root: state.latest_block_header().hash_tree_root(),
        state_root: Root::ZERO,
        body,
    };

    let mut post = state.clone();
    let BeaconState::Gloas(_) = &post else {
        unreachable!("checked above")
    };
    stf::gloas::process_block(&mut post, &block, config, &CommitteeCache::default())?;
    block.state_root = post.hash_tree_root();

    let envelope = ExecutionPayloadEnvelope {
        payload: inputs.execution_payload,
        execution_requests: inputs.execution_requests,
        builder_index: constants::BUILDER_INDEX_SELF_BUILD,
        beacon_block_root: block.hash_tree_root(),
        parent_beacon_block_root: block.parent_root,
    };
    check_envelope(&post, &envelope, config)?;
    Ok(GloasProduced { block, envelope })
}

/// `verify_execution_payload_envelope` (gloas `fork-choice.md`) without its
/// signature check and its engine call, against `post`, the state after the
/// block the envelope belongs to.
///
/// Mirrors [`stf::gloas::verify_execution_payload_envelope`] condition for
/// condition rather than calling it, because that function verifies the
/// signature first and the producer has none to give yet: the proposer signs
/// the envelope after this node hands it over.
fn check_envelope(
    post: &BeaconState,
    envelope: &ExecutionPayloadEnvelope,
    config: &Config,
) -> Result<()> {
    let payload = &envelope.payload;
    let mut header = post.latest_block_header().clone();
    header.state_root = post.compute_state_root();
    verify(
        envelope.beacon_block_root == header.hash_tree_root(),
        "envelope.beacon_block_root == hash_tree_root(header)",
    )?;
    verify(
        envelope.parent_beacon_block_root == post.latest_block_header().parent_root,
        "envelope.parent_beacon_block_root == state.latest_block_header.parent_root",
    )?;
    let inner = gloas_state_ref(post, "check_envelope")?;
    let bid = &inner.latest_execution_payload_bid;
    verify(
        envelope.builder_index == bid.builder_index,
        "envelope.builder_index == bid.builder_index",
    )?;
    verify(
        payload.prev_randao == bid.prev_randao,
        "payload.prev_randao == bid.prev_randao",
    )?;
    verify(
        payload.gas_limit == bid.gas_limit,
        "payload.gas_limit == bid.gas_limit",
    )?;
    verify(
        payload.block_hash == bid.block_hash,
        "payload.block_hash == bid.block_hash",
    )?;
    verify(
        envelope.execution_requests.hash_tree_root() == bid.execution_requests_root,
        "hash_tree_root(envelope.execution_requests) == bid.execution_requests_root",
    )?;
    verify(
        payload.slot_number == post.slot(),
        "payload.slot_number == state.slot",
    )?;
    verify(
        payload.parent_hash == inner.latest_block_hash,
        "payload.parent_hash == state.latest_block_hash",
    )?;
    verify(
        payload.timestamp == stf::bellatrix::compute_timestamp_at_slot(post, post.slot(), config),
        "payload.timestamp == compute_time_at_slot(state, state.slot)",
    )?;
    verify(
        payload.withdrawals.hash_tree_root() == inner.payload_expected_withdrawals.hash_tree_root(),
        "hash_tree_root(payload.withdrawals) == hash_tree_root(state.payload_expected_withdrawals)",
    )?;
    Ok(())
}

#[cfg(test)]
mod gloas_block_production_tests {
    use super::super::stf::ExecutionEngine;
    use super::*;
    use crate::beacon::ForkName;
    use crate::beacon::block_production::advance_to_slot;
    use crate::beacon::helpers::accessors::get_domain;
    use crate::beacon::helpers::fulu::initialize_proposer_lookahead;
    use crate::beacon::helpers::gloas::compute_ptc;
    use crate::beacon::helpers::misc::compute_signing_root;
    use crate::beacon::helpers::test_state::{sign_for, with_signing_validators_at};
    use ethlambda_types::beacon::containers::bellatrix::{ExtraData, LogsBloom};
    use ethlambda_types::beacon::primitives::Uint256;

    const PARENT_BLOCK_HASH: u8 = 0x11;
    const GRANDPARENT_BLOCK_HASH: u8 = 0x10;

    fn config() -> Config {
        Config::mainnet().with_fork_epoch(ForkName::Gloas, 0)
    }

    /// A gloas state at slot 33 whose parent block (slot 32) revealed a payload,
    /// its PTC for slot 32 filled from the real registry, with the lookahead
    /// and sync committee a real registry would give it.
    fn state_to_build_on() -> BeaconState {
        let mut state = with_signing_validators_at(ForkName::Gloas, 64);
        let lookahead = initialize_proposer_lookahead(&state).unwrap();
        let sync_committee =
            crate::beacon::helpers::altair::get_next_sync_committee(&state).unwrap();
        let ptc = compute_ptc(&state, state.slot(), &CommitteeCache::default()).unwrap();
        let BeaconState::Gloas(inner) = &mut state else {
            unreachable!("built as gloas")
        };
        inner.proposer_lookahead = lookahead.try_into().unwrap();
        inner.current_sync_committee = sync_committee.clone();
        inner.next_sync_committee = sync_committee;
        inner.latest_block_header.slot = inner.slot;
        inner.latest_block_hash = ExecutionBlockHash::repeat_byte(GRANDPARENT_BLOCK_HASH);
        inner.latest_execution_payload_bid = ExecutionPayloadBid {
            parent_block_hash: ExecutionBlockHash::repeat_byte(GRANDPARENT_BLOCK_HASH),
            block_hash: ExecutionBlockHash::repeat_byte(PARENT_BLOCK_HASH),
            gas_limit: 30_000_000,
            slot: inner.slot,
            builder_index: constants::BUILDER_INDEX_SELF_BUILD,
            execution_requests_root: ExecutionRequests::default().hash_tree_root(),
            ..Default::default()
        };
        // The window entry `get_ptc` reads for a slot of the state's own epoch.
        let window_index =
            (preset::SLOTS_PER_EPOCH + inner.slot % preset::SLOTS_PER_EPOCH) as usize;
        inner.ptc_window[window_index] = ptc;
        let slot = state.slot() + 1;
        advance_to_slot(&state, slot, &config()).unwrap()
    }

    fn payload_for(inputs: &GloasPayloadInputs) -> ExecutionPayload {
        ExecutionPayload {
            parent_hash: inputs.head_block_hash,
            fee_recipient: Default::default(),
            state_root: Bytes32::repeat_byte(1),
            receipts_root: Bytes32::repeat_byte(2),
            logs_bloom: LogsBloom::try_from(vec![0u8; preset::BYTES_PER_LOGS_BLOOM]).unwrap(),
            prev_randao: inputs.prev_randao,
            block_number: 7,
            gas_limit: inputs.target_gas_limit,
            gas_used: 0,
            timestamp: inputs.timestamp,
            extra_data: ExtraData::default(),
            base_fee_per_gas: Uint256::from_u128(7),
            block_hash: ExecutionBlockHash::repeat_byte(0x22),
            transactions: Default::default(),
            withdrawals: inputs.withdrawals.clone().into(),
            blob_gas_used: 0,
            excess_blob_gas: 0,
            block_access_list: Default::default(),
            slot_number: inputs.slot_number,
        }
    }

    fn randao_reveal(state: &BeaconState) -> BlsSignature {
        let proposer = get_beacon_proposer_index(state).unwrap();
        let epoch = get_current_epoch(state);
        let domain = get_domain(state, constants::DOMAIN_RANDAO, Some(epoch));
        sign_for(
            proposer as usize,
            compute_signing_root(epoch.hash_tree_root(), domain),
        )
    }

    fn produce(
        state: &BeaconState,
        build_on_full: bool,
        payload_attestations: Vec<PayloadAttestation>,
    ) -> Result<GloasProduced> {
        let requests = ExecutionRequests::default();
        let inputs = gloas_payload_inputs(state, build_on_full, &requests, &config())?;
        assemble_gloas_block(
            state,
            GloasBlockInputs {
                randao_reveal: randao_reveal(state),
                graffiti: Bytes32::repeat_byte(7),
                attestations: Vec::new(),
                payload_attestations,
                parent_execution_requests: requests,
                execution_payload: payload_for(&inputs),
                blob_kzg_commitments: vec![KzgCommitment([5; 48])],
                execution_requests: ExecutionRequests::default(),
            },
            &config(),
        )
    }

    /// A vote on the parent block (slot 32) signed by `validator`.
    fn ptc_message(
        state: &BeaconState,
        validator: ValidatorIndex,
        data: PayloadAttestationData,
    ) -> PayloadAttestationMessage {
        let domain = get_domain(
            state,
            constants::DOMAIN_PTC_ATTESTER,
            Some(ethlambda_types::beacon::signing::compute_epoch_at_slot(
                data.slot,
            )),
        );
        PayloadAttestationMessage {
            validator_index: validator,
            data,
            signature: sign_for(
                validator as usize,
                compute_signing_root(data.hash_tree_root(), domain),
            ),
        }
    }

    fn parent_vote(state: &BeaconState, present: bool) -> PayloadAttestationData {
        PayloadAttestationData {
            beacon_block_root: state.latest_block_header().hash_tree_root(),
            slot: state.slot() - 1,
            payload_present: present,
            blob_data_available: true,
        }
    }

    #[test]
    fn a_self_built_block_passes_the_stf_with_a_real_signature_and_its_envelope_verifies() {
        let state = state_to_build_on();
        let produced = produce(&state, true, Vec::new()).unwrap();
        let GloasProduced { block, envelope } = &produced;

        // Signed by the proposer, as a validator client would.
        let signed = gloas::SignedBeaconBlock {
            message: block.clone(),
            signature: {
                let domain = get_domain(&state, constants::DOMAIN_BEACON_PROPOSER, None);
                sign_for(
                    block.proposer_index as usize,
                    compute_signing_root(block.hash_tree_root(), domain),
                )
            },
        };
        let wrapped = ethlambda_types::beacon::containers::SignedBeaconBlock::Gloas(signed);
        assert!(stf::verify_block_signature(&state, &wrapped));

        // Applying it again, the way a peer importing it would, lands on the
        // state root it claims.
        let mut post = state.clone();
        stf::block::process_block(
            &mut post,
            &wrapped,
            &config(),
            &ExecutionEngine::valid(),
            &CommitteeCache::default(),
        )
        .unwrap();
        assert_eq!(block.state_root, post.hash_tree_root());

        // The envelope, signed by the same proposer under DOMAIN_BEACON_BUILDER,
        // passes the full import-side check.
        let domain = get_domain(&post, constants::DOMAIN_BEACON_BUILDER, None);
        let signed_envelope = gloas::SignedExecutionPayloadEnvelope {
            message: envelope.clone(),
            signature: sign_for(
                block.proposer_index as usize,
                compute_signing_root(envelope.hash_tree_root(), domain),
            ),
        };
        stf::gloas::verify_execution_payload_envelope(
            &post,
            &signed_envelope,
            &config(),
            &ExecutionEngine::valid(),
        )
        .unwrap();
        assert_eq!(envelope.beacon_block_root, block.hash_tree_root());
        assert_eq!(envelope.parent_beacon_block_root, block.parent_root);
    }

    #[test]
    fn the_bid_is_a_zero_value_self_build_over_the_payload() {
        let state = state_to_build_on();
        let produced = produce(&state, true, Vec::new()).unwrap();
        let signed_bid = &produced.block.body.signed_execution_payload_bid;
        let bid = &signed_bid.message;
        let payload = &produced.envelope.payload;
        assert_eq!(bid.builder_index, constants::BUILDER_INDEX_SELF_BUILD);
        assert_eq!((bid.value, bid.execution_payment), (0, 0));
        assert_eq!(
            signed_bid.signature,
            BlsSignature(bls::G2_POINT_AT_INFINITY)
        );
        assert_eq!(bid.slot, state.slot());
        assert_eq!(bid.parent_block_hash, payload.parent_hash);
        assert_eq!(bid.block_hash, payload.block_hash);
        assert_eq!(bid.prev_randao, payload.prev_randao);
        assert_eq!(bid.gas_limit, payload.gas_limit);
        assert_eq!(
            bid.parent_block_root,
            state.latest_block_header().hash_tree_root()
        );
        assert_eq!(bid.blob_kzg_commitments.len(), 1);
        assert_eq!(
            bid.execution_requests_root,
            produced.envelope.execution_requests.hash_tree_root()
        );
    }

    #[test]
    fn building_on_full_extends_the_parent_payload_and_on_empty_skips_it() {
        let state = state_to_build_on();
        let requests = ExecutionRequests::default();
        let full = gloas_payload_inputs(&state, true, &requests, &config()).unwrap();
        let empty = gloas_payload_inputs(&state, false, &requests, &config()).unwrap();
        assert_eq!(
            full.head_block_hash,
            ExecutionBlockHash::repeat_byte(PARENT_BLOCK_HASH)
        );
        assert_eq!(
            empty.head_block_hash,
            ExecutionBlockHash::repeat_byte(GRANDPARENT_BLOCK_HASH)
        );
        assert_eq!(full.slot_number, state.slot());
        assert_eq!(full.target_gas_limit, 30_000_000);
        assert_eq!(
            full.parent_beacon_block_root,
            state.latest_block_header().hash_tree_root()
        );

        // Both are valid blocks, and the empty one's bid names the older hash.
        let on_full = produce(&state, true, Vec::new()).unwrap();
        let on_empty = produce(&state, false, Vec::new()).unwrap();
        let parent_hash = |produced: &GloasProduced| {
            produced
                .block
                .body
                .signed_execution_payload_bid
                .message
                .parent_block_hash
        };
        assert_eq!(parent_hash(&on_full), full.head_block_hash);
        assert_eq!(parent_hash(&on_empty), empty.head_block_hash);
    }

    #[test]
    fn a_payload_on_the_wrong_parent_is_refused_before_signing() {
        let state = state_to_build_on();
        let requests = ExecutionRequests::default();
        let inputs = gloas_payload_inputs(&state, true, &requests, &config()).unwrap();
        let mut payload = payload_for(&inputs);
        payload.parent_hash = ExecutionBlockHash::repeat_byte(9);
        let result = assemble_gloas_block(
            &state,
            GloasBlockInputs {
                randao_reveal: randao_reveal(&state),
                graffiti: Bytes32::ZERO,
                attestations: Vec::new(),
                payload_attestations: Vec::new(),
                parent_execution_requests: requests,
                execution_payload: payload,
                blob_kzg_commitments: Vec::new(),
                execution_requests: ExecutionRequests::default(),
            },
            &config(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn a_withdrawal_set_the_state_does_not_expect_is_refused() {
        let state = state_to_build_on();
        let requests = ExecutionRequests::default();
        let inputs = gloas_payload_inputs(&state, true, &requests, &config()).unwrap();
        let mut payload = payload_for(&inputs);
        payload.withdrawals = vec![Withdrawal {
            index: 99,
            validator_index: 1,
            address: Default::default(),
            amount: 1,
        }]
        .into();
        let produced = assemble_gloas_block(
            &state,
            GloasBlockInputs {
                randao_reveal: randao_reveal(&state),
                graffiti: Bytes32::ZERO,
                attestations: Vec::new(),
                payload_attestations: Vec::new(),
                parent_execution_requests: requests,
                execution_payload: payload,
                blob_kzg_commitments: Vec::new(),
                execution_requests: ExecutionRequests::default(),
            },
            &config(),
        );
        assert!(produced.is_err());
    }

    #[test]
    fn payload_attestations_set_every_seat_and_aggregate_every_signature() {
        let state = state_to_build_on();
        let ptc = get_ptc(&state, state.slot() - 1, &config()).unwrap();
        let first = ptc[0];
        let second = *ptc.iter().find(|validator| **validator != first).unwrap();
        let data = parent_vote(&state, true);
        let messages = vec![
            ptc_message(&state, first, data),
            ptc_message(&state, second, data),
            // Another view of the payload: its own aggregate.
            ptc_message(&state, first, parent_vote(&state, false)),
        ];
        let parent_root = state.latest_block_header().hash_tree_root();
        let packed =
            pack_payload_attestations(&state, parent_root, state.slot() - 1, messages, &config());

        assert_eq!(packed.len(), 2);
        let aggregate = &packed[0];
        assert_eq!(aggregate.data, data);
        let seats = |validator: ValidatorIndex| ptc.iter().filter(|v| **v == validator).count();
        let expected_bits: Vec<usize> = ptc
            .iter()
            .enumerate()
            .filter(|(_, validator)| **validator == first || **validator == second)
            .map(|(position, _)| position)
            .collect();
        let set: Vec<usize> = (0..preset::PTC_SIZE)
            .filter(|&position| aggregate.aggregation_bits.get(position).unwrap_or(false))
            .collect();
        assert_eq!(set, expected_bits);
        assert_eq!(set.len(), seats(first) + seats(second));

        // It rides in a block that passes the full STF.
        let produced = produce(&state, true, packed).unwrap();
        assert_eq!(produced.block.body.payload_attestations.len(), 2);
    }

    #[test]
    fn payload_attestations_for_another_parent_or_a_distant_slot_are_left_out() {
        let state = state_to_build_on();
        let ptc = get_ptc(&state, state.slot() - 1, &config()).unwrap();
        let data = parent_vote(&state, true);
        let message = ptc_message(&state, ptc[0], data);
        let parent_root = state.latest_block_header().hash_tree_root();

        // Not the parent block.
        assert!(
            pack_payload_attestations(
                &state,
                Root::repeat_byte(9),
                state.slot() - 1,
                vec![message.clone()],
                &config()
            )
            .is_empty()
        );
        // The parent is two slots back: nothing to attest to.
        assert!(
            pack_payload_attestations(
                &state,
                parent_root,
                state.slot() - 2,
                vec![message],
                &config()
            )
            .is_empty()
        );
        // A forged signature does not verify, so the aggregate is dropped.
        let mut forged = ptc_message(&state, ptc[0], data);
        forged.signature = ptc_message(&state, ptc[0], parent_vote(&state, false)).signature;
        assert!(
            pack_payload_attestations(
                &state,
                parent_root,
                state.slot() - 1,
                vec![forged],
                &config()
            )
            .is_empty()
        );
    }

    /// A single-committee vote at slot 32 signed by committee 0's first member.
    fn vote(state: &BeaconState, beacon_block_root: Root, index: u64) -> electra::Attestation {
        use crate::beacon::helpers::accessors::{get_beacon_committee, get_block_root};
        let epoch = get_current_epoch(state);
        let data = ethlambda_types::beacon::containers::shared::AttestationData {
            slot: state.slot() - 1,
            index,
            beacon_block_root,
            source: state.current_justified_checkpoint(),
            target: ethlambda_types::beacon::containers::shared::Checkpoint {
                epoch,
                root: get_block_root(state, epoch).unwrap(),
            },
        };
        let members = get_beacon_committee(state, data.slot, 0).unwrap();
        let domain = get_domain(state, constants::DOMAIN_BEACON_ATTESTER, Some(epoch));
        let mut aggregation_bits = electra::AggregationBits::with_length(members.len()).unwrap();
        aggregation_bits.set(0, true).unwrap();
        let mut committee_bits = electra::CommitteeBits::default();
        committee_bits.set(0, true).unwrap();
        electra::Attestation {
            aggregation_bits,
            data,
            signature: sign_for(
                members[0] as usize,
                compute_signing_root(data.hash_tree_root(), domain),
            ),
            committee_bits,
        }
    }

    #[test]
    fn attestations_honor_the_gloas_payload_index_rules() {
        let state = state_to_build_on();
        let parent_root = state.latest_block_header().hash_tree_root();
        // A vote for an older block may name either payload status.
        let elsewhere = Root::repeat_byte(1);
        assert_eq!(
            pack_gloas_attestations(&state, vec![vote(&state, elsewhere, 1)]).len(),
            1
        );
        // A vote for the block of its own slot must say 0, and none says 2.
        assert!(pack_gloas_attestations(&state, vec![vote(&state, parent_root, 1)]).is_empty());
        assert_eq!(
            pack_gloas_attestations(&state, vec![vote(&state, parent_root, 0)]).len(),
            1
        );
        assert!(pack_gloas_attestations(&state, vec![vote(&state, elsewhere, 2)]).is_empty());

        // The packed vote rides in a block that passes the full STF.
        let packed = pack_gloas_attestations(&state, vec![vote(&state, parent_root, 0)]);
        let requests = ExecutionRequests::default();
        let inputs = gloas_payload_inputs(&state, true, &requests, &config()).unwrap();
        assemble_gloas_block(
            &state,
            GloasBlockInputs {
                randao_reveal: randao_reveal(&state),
                graffiti: Bytes32::ZERO,
                attestations: packed,
                payload_attestations: Vec::new(),
                parent_execution_requests: requests,
                execution_payload: payload_for(&inputs),
                blob_kzg_commitments: Vec::new(),
                execution_requests: ExecutionRequests::default(),
            },
            &config(),
        )
        .unwrap();
    }

    #[test]
    fn column_sidecars_carry_every_cell_and_verify_against_the_commitments() {
        // A blob of small field elements, valid and cheap to commit to.
        let mut blob = vec![0u8; preset::BYTES_PER_BLOB];
        for (i, element) in blob.chunks_mut(32).enumerate() {
            element[31] = (i % 200) as u8;
        }
        let commitment = crate::beacon::kzg::blob_to_kzg_commitment(&blob).unwrap();
        let (_, proofs) = crate::beacon::kzg::compute_cells_and_kzg_proofs(&blob).unwrap();
        let root = Root::repeat_byte(3);
        let sidecars = gloas_data_column_sidecars(root, 33, &[blob], &proofs[..]).unwrap();

        assert_eq!(sidecars.len(), preset::NUMBER_OF_COLUMNS);
        for (index, sidecar) in sidecars.iter().enumerate() {
            assert_eq!((sidecar.index, sidecar.slot), (index as u64, 33));
            assert_eq!(sidecar.beacon_block_root, root);
            assert!(
                crate::beacon::fork_choice::gloas_verify_data_column_sidecar(
                    sidecar,
                    &[commitment]
                )
            );
        }
        for index in [0, 77, preset::NUMBER_OF_COLUMNS - 1] {
            assert!(
                crate::beacon::fork_choice::gloas_verify_data_column_sidecar_kzg_proofs(
                    &sidecars[index],
                    &[commitment]
                )
                .unwrap()
            );
        }
        // A proof count that does not fit the blobs is refused.
        assert!(
            gloas_data_column_sidecars(root, 33, &[vec![0; preset::BYTES_PER_BLOB]], &[]).is_err()
        );
    }

    #[test]
    fn a_gloas_request_list_round_trips_and_a_malformed_one_is_refused() {
        let requests = ExecutionRequests {
            builder_exits: vec![gloas::BuilderExitRequest::default()].into(),
            ..Default::default()
        };
        let list = stf::gloas::get_execution_requests_list(&requests);
        assert_eq!(parse_gloas_execution_requests(&list).unwrap(), requests);
        assert_eq!(
            parse_gloas_execution_requests(&[]).unwrap(),
            ExecutionRequests::default()
        );
        let exit = vec![constants::BUILDER_EXIT_REQUEST_TYPE, 1];
        let deposit = vec![constants::DEPOSIT_REQUEST_TYPE, 1];
        assert!(parse_gloas_execution_requests(&[exit, deposit]).is_err());
        assert!(
            parse_gloas_execution_requests(&[vec![constants::BUILDER_DEPOSIT_REQUEST_TYPE]])
                .is_err()
        );
        assert!(parse_gloas_execution_requests(&[vec![0x7f, 0]]).is_err());
    }
}
