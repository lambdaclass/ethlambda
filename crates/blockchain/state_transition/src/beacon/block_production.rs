//! Assembling an unsigned beacon block for a proposer, per phase0's
//! `validator.md` ("Block proposal") as each later fork's `validator.md`
//! extends it.
//!
//! Electra and fulu only: electra is the earliest fork a validator client
//! served here submits attestations for (`SingleAttestation`), and fulu reuses
//! electra's block containers unchanged.
//!
//! The pieces the execution client supplies (the payload, its blob commitments
//! and its request list) arrive already built; this module decides everything
//! the consensus layer decides, and computes the state root by running the
//! block through `process_block` on a copy of the state, the way
//! `validator.md` describes (`compute_new_state_root`).

use ethlambda_types::beacon::{
    constants,
    containers::{
        BeaconState, SignedBeaconBlock,
        altair::SyncAggregate,
        capella::Withdrawal,
        deneb::ExecutionPayload,
        electra::{
            self, AggregationBits, Attestation, BeaconBlock, BeaconBlockBody, CommitteeBits,
            ConsolidationRequest, DepositRequest, ExecutionRequests, WithdrawalRequest,
        },
    },
    preset,
    primitives::{
        BlsSignature, Bytes32, ExecutionBlockHash, HashTreeRoot as _, KzgCommitment, Root, Slot,
    },
    signing::compute_epoch_at_slot,
};
use libssz::SszDecode as _;
use libssz_types::SszList;

use super::attestation_pool::single_committee;
use super::bls;
use super::config::Config;
use super::error::{Error, Result, verify};
use super::helpers::accessors::{
    CommitteeCache, get_beacon_proposer_index, get_current_epoch, get_previous_epoch,
    get_randao_mix,
};
use super::helpers::electra::get_attesting_indices;
use super::stf::{self, ExecutionEngine};

/// `state` advanced through empty slots to `slot`, as a block for `slot` is
/// applied to it. A state already at `slot` is returned as it is.
pub fn advance_to_slot(state: &BeaconState, slot: Slot, config: &Config) -> Result<BeaconState> {
    let mut advanced = state.clone();
    if advanced.slot() < slot {
        stf::process_slots(&mut advanced, slot, config)?;
    }
    Ok(advanced)
}

/// What the execution client needs to build the payload for the slot
/// `state` has been advanced to (`PayloadAttributesV3`, less the fee
/// recipient and the parent beacon block root, which the caller knows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadInputs {
    pub timestamp: u64,
    pub prev_randao: Bytes32,
    pub withdrawals: Vec<Withdrawal>,
    /// The execution block the payload must extend.
    pub parent_hash: ExecutionBlockHash,
}

/// The payload inputs for `state`'s slot: the conditions
/// `process_execution_payload` and `process_withdrawals` will hold the payload
/// to, computed from the same state.
pub fn payload_inputs(state: &BeaconState, config: &Config) -> Result<PayloadInputs> {
    let parent_hash = match state {
        BeaconState::Electra(state) => state.latest_execution_payload_header.block_hash,
        BeaconState::Fulu(state) => state.latest_execution_payload_header.block_hash,
        _ => return Err(Error::SpecAssert("block production is electra and later")),
    };
    Ok(PayloadInputs {
        timestamp: stf::bellatrix::compute_timestamp_at_slot(state, state.slot(), config),
        prev_randao: get_randao_mix(state, get_current_epoch(state)),
        withdrawals: stf::electra::get_expected_withdrawals(state)?.0,
        parent_hash,
    })
}

/// A sync aggregate no member contributed to. Valid, it only forfeits the
/// rewards: `process_sync_aggregate` requires the empty signature to be the
/// G2 point at infinity rather than zero bytes.
pub fn empty_sync_aggregate() -> SyncAggregate {
    SyncAggregate {
        sync_committee_bits: Default::default(),
        sync_committee_signature: BlsSignature(bls::G2_POINT_AT_INFINITY),
    }
}

/// The inverse of `get_execution_requests_list`: the execution client's
/// EIP-7685 request list back into the block body's `ExecutionRequests`.
///
/// Each element is a request-type byte followed by the SSZ of that type's
/// list. The Engine API requires the types strictly ascending and no element
/// empty, which is checked rather than trusted, since a list this node
/// accepted would go into a block its peers then reject.
pub fn parse_execution_requests(list: &[Vec<u8>]) -> Result<ExecutionRequests> {
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
                requests.deposits =
                    SszList::<DepositRequest, _>::from_ssz_bytes(data).map_err(malformed)?;
            }
            constants::WITHDRAWAL_REQUEST_TYPE => {
                requests.withdrawals =
                    SszList::<WithdrawalRequest, _>::from_ssz_bytes(data).map_err(malformed)?;
            }
            constants::CONSOLIDATION_REQUEST_TYPE => {
                requests.consolidations =
                    SszList::<ConsolidationRequest, _>::from_ssz_bytes(data).map_err(malformed)?;
            }
            _ => return Err(Error::SpecAssert("a known execution request type")),
        }
    }
    Ok(requests)
}

/// Pick the attestations for a block at `state`'s slot from `candidates`,
/// each covering a single committee.
///
/// Keeps only what `process_attestation` accepts at this slot: included at
/// least `MIN_ATTESTATION_INCLUSION_DELAY` after its own slot, targeting the
/// current or previous epoch, and sourced from the justified checkpoint that
/// target implies. Of those, only candidates with at least one attester the
/// state has not yet credited for that epoch: an attestation already on chain
/// earns nothing again, and with room for only `MAX_ATTESTATIONS_ELECTRA`
/// per block, re-including it would crowd out ones that still count.
/// Candidates voting on the same `AttestationData` are merged into one electra
/// `Attestation` spanning their committees (EIP-7549's on-chain aggregation),
/// ordered by how many new attesters they bring, then newest first.
pub fn pack_attestations(state: &BeaconState, candidates: Vec<Attestation>) -> Vec<Attestation> {
    let current_epoch = get_current_epoch(state);
    let previous_epoch = get_previous_epoch(state);
    let includable = |attestation: &Attestation| {
        let data = &attestation.data;
        let target_epoch = data.target.epoch;
        let expected_source = if target_epoch == current_epoch {
            state.current_justified_checkpoint()
        } else {
            state.previous_justified_checkpoint()
        };
        data.slot + preset::MIN_ATTESTATION_INCLUSION_DELAY <= state.slot()
            && (target_epoch == current_epoch || target_epoch == previous_epoch)
            && target_epoch == compute_epoch_at_slot(data.slot)
            && data.source == expected_source
    };

    // How many of an attestation's attesters the state has not yet credited
    // for its target epoch: a participation byte of zero is a validator no
    // attestation for that epoch has counted yet.
    let Ok((previous_participation, current_participation, _)) = state.altair_validator_lists()
    else {
        return Vec::new();
    };
    let committees = CommitteeCache::default();
    let new_attesters = |attestation: &Attestation| -> usize {
        let participation = if attestation.data.target.epoch == current_epoch {
            current_participation
        } else {
            previous_participation
        };
        get_attesting_indices(state, attestation, &committees)
            .map(|indices| {
                indices
                    .iter()
                    .filter(|&&index| participation.get(index as usize) == Some(&0))
                    .count()
            })
            .unwrap_or(0)
    };

    // Grouped by data, each group's committees in ascending order, which is
    // the order `get_attesting_indices` walks `committee_bits` in, with the
    // group's total of new attesters.
    let mut groups: std::collections::BTreeMap<Root, (usize, Vec<(u64, Attestation)>)> =
        Default::default();
    for attestation in candidates.into_iter().filter(includable) {
        let Some(committee) = single_committee(&attestation) else {
            continue;
        };
        let new = new_attesters(&attestation);
        if new == 0 {
            continue;
        }
        let (total, group) = groups.entry(attestation.data.hash_tree_root()).or_default();
        if group.iter().all(|(index, _)| *index != committee) {
            *total += new;
            group.push((committee, attestation));
        }
    }

    let mut merged: Vec<(usize, Attestation)> = groups
        .into_values()
        .filter_map(|(new, mut group)| {
            group.sort_by_key(|(committee, _)| *committee);
            merge_committees(group).map(|attestation| (new, attestation))
        })
        .collect();
    merged.sort_by_key(|(new, attestation)| {
        (
            std::cmp::Reverse(*new),
            std::cmp::Reverse(attestation.data.slot),
        )
    });
    merged.truncate(preset::MAX_ATTESTATIONS_ELECTRA);
    merged
        .into_iter()
        .map(|(_, attestation)| attestation)
        .collect()
}

/// One attestation over every committee in `group`, which shares one
/// `AttestationData`: their aggregation bits concatenated in committee order,
/// and their signatures aggregated.
fn merge_committees(group: Vec<(u64, Attestation)>) -> Option<Attestation> {
    let data = group.first()?.1.data;
    let total: usize = group.iter().map(|(_, a)| a.aggregation_bits.len()).sum();
    let mut aggregation_bits = AggregationBits::with_length(total).ok()?;
    let mut committee_bits = CommitteeBits::default();
    let mut signatures = Vec::with_capacity(group.len());
    let mut offset = 0;
    for (committee, attestation) in &group {
        committee_bits.set(*committee as usize, true).ok()?;
        for position in 0..attestation.aggregation_bits.len() {
            if attestation.aggregation_bits.get(position).unwrap_or(false) {
                aggregation_bits.set(offset + position, true).ok()?;
            }
        }
        offset += attestation.aggregation_bits.len();
        signatures.push(attestation.signature);
    }
    Some(Attestation {
        aggregation_bits,
        data,
        signature: bls::aggregate(&signatures).ok()?,
        committee_bits,
    })
}

/// What a block body carries beyond what this module derives from the state.
#[derive(Debug, Clone)]
pub struct BlockInputs {
    pub randao_reveal: BlsSignature,
    pub graffiti: Bytes32,
    pub attestations: Vec<Attestation>,
    pub execution_payload: ExecutionPayload,
    pub blob_kzg_commitments: Vec<KzgCommitment>,
    pub execution_requests: ExecutionRequests,
}

/// The unsigned block for the slot `state` has been advanced to, with its
/// state root computed.
///
/// The body votes the state's own `eth1_data` and carries no deposits (the
/// deposit contract's log has been replaced by EIP-6110's requests), no
/// slashings, exits or credential changes (this node pools none), and an empty
/// sync aggregate. The block is run through `process_block` on a copy of
/// `state` with an execution engine that accepts the payload, which is the
/// node's own execution client's payload; that run is also what rejects a body
/// the network would, before anything is signed.
pub fn assemble_block(
    state: &BeaconState,
    inputs: BlockInputs,
    config: &Config,
) -> Result<BeaconBlock> {
    let body = BeaconBlockBody {
        randao_reveal: inputs.randao_reveal,
        eth1_data: state.eth1_data().clone(),
        graffiti: inputs.graffiti,
        attestations: inputs
            .attestations
            .try_into()
            .map_err(|_| Error::SpecAssert("len(attestations) <= MAX_ATTESTATIONS_ELECTRA"))?,
        sync_aggregate: empty_sync_aggregate(),
        execution_payload: inputs.execution_payload,
        blob_kzg_commitments: inputs
            .blob_kzg_commitments
            .try_into()
            .map_err(|_| Error::SpecAssert("len(blob_kzg_commitments) within bound"))?,
        execution_requests: inputs.execution_requests,
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

    let signed = electra::SignedBeaconBlock {
        message: block.clone(),
        signature: BlsSignature::default(),
    };
    let wrapped = match state {
        BeaconState::Electra(_) => SignedBeaconBlock::Electra(signed),
        BeaconState::Fulu(_) => SignedBeaconBlock::Fulu(signed),
        _ => return Err(Error::SpecAssert("block production is electra and later")),
    };
    let mut post = state.clone();
    stf::block::process_block(
        &mut post,
        &wrapped,
        config,
        &ExecutionEngine::valid(),
        &CommitteeCache::default(),
    )?;
    block.state_root = post.hash_tree_root();
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::ForkName;
    use crate::beacon::helpers::accessors::get_domain;
    use crate::beacon::helpers::fulu::initialize_proposer_lookahead;
    use crate::beacon::helpers::misc::compute_signing_root;
    use crate::beacon::helpers::test_state::{sign_for, with_signing_validators_at};

    /// A fulu state one epoch in, its lookahead and sync committee filled from
    /// its real registry (the builder leaves both as placeholders), advanced one
    /// slot so a block can be built on it.
    fn state_to_build_on() -> BeaconState {
        let mut state = with_signing_validators_at(ForkName::Fulu, 64);
        let lookahead = initialize_proposer_lookahead(&state).unwrap();
        let sync_committee =
            crate::beacon::helpers::altair::get_next_sync_committee(&state).unwrap();
        let BeaconState::Fulu(inner) = &mut state else {
            unreachable!("built as fulu")
        };
        inner.proposer_lookahead = lookahead.try_into().unwrap();
        inner.current_sync_committee = sync_committee.clone();
        inner.next_sync_committee = sync_committee;
        let slot = state.slot() + 1;
        advance_to_slot(&state, slot, &Config::mainnet()).unwrap()
    }

    fn payload_for(state: &BeaconState) -> ExecutionPayload {
        let inputs = payload_inputs(state, &Config::mainnet()).unwrap();
        ExecutionPayload {
            parent_hash: inputs.parent_hash,
            prev_randao: inputs.prev_randao,
            timestamp: inputs.timestamp,
            withdrawals: inputs.withdrawals.try_into().unwrap(),
            ..BeaconBlockBody::empty().execution_payload
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

    #[test]
    fn an_assembled_block_passes_process_block_and_names_its_post_state() {
        let state = state_to_build_on();
        let inputs = BlockInputs {
            randao_reveal: randao_reveal(&state),
            graffiti: Bytes32::repeat_byte(7),
            attestations: Vec::new(),
            execution_payload: payload_for(&state),
            blob_kzg_commitments: Vec::new(),
            execution_requests: ExecutionRequests::default(),
        };
        let block = assemble_block(&state, inputs, &Config::mainnet()).unwrap();

        assert_eq!(block.slot, state.slot());
        assert_eq!(
            block.proposer_index,
            get_beacon_proposer_index(&state).unwrap()
        );
        // Applying it again, the way a peer importing it would, lands on the
        // state root it claims.
        let mut post = state.clone();
        let signed = SignedBeaconBlock::Fulu(electra::SignedBeaconBlock {
            message: block.clone(),
            signature: BlsSignature::default(),
        });
        stf::block::process_block(
            &mut post,
            &signed,
            &Config::mainnet(),
            &ExecutionEngine::valid(),
            &CommitteeCache::default(),
        )
        .unwrap();
        assert_eq!(block.state_root, post.hash_tree_root());
    }

    #[test]
    fn a_payload_on_the_wrong_parent_is_refused_before_signing() {
        let state = state_to_build_on();
        let mut payload = payload_for(&state);
        payload.parent_hash = ExecutionBlockHash::repeat_byte(9);
        let inputs = BlockInputs {
            randao_reveal: randao_reveal(&state),
            graffiti: Bytes32::ZERO,
            attestations: Vec::new(),
            execution_payload: payload,
            blob_kzg_commitments: Vec::new(),
            execution_requests: ExecutionRequests::default(),
        };
        assert!(assemble_block(&state, inputs, &Config::mainnet()).is_err());
    }

    /// A single-committee aggregate over `data` with the given member bits.
    fn committee_aggregate(
        data: ethlambda_types::beacon::containers::shared::AttestationData,
        committee: usize,
        bits: &[bool],
        signer: usize,
    ) -> Attestation {
        let mut aggregation_bits = AggregationBits::with_length(bits.len()).unwrap();
        for (i, bit) in bits.iter().enumerate() {
            aggregation_bits.set(i, *bit).unwrap();
        }
        let mut committee_bits = CommitteeBits::default();
        committee_bits.set(committee, true).unwrap();
        Attestation {
            aggregation_bits,
            data,
            signature: sign_for(signer, data.hash_tree_root()),
            committee_bits,
        }
    }

    #[test]
    fn committees_voting_alike_are_merged_and_the_too_recent_left_out() {
        let state = state_to_build_on();
        let data = ethlambda_types::beacon::containers::shared::AttestationData {
            slot: state.slot() - 1,
            index: 0,
            beacon_block_root: Root::repeat_byte(1),
            source: state.current_justified_checkpoint(),
            target: ethlambda_types::beacon::containers::shared::Checkpoint {
                epoch: get_current_epoch(&state),
                root: Root::repeat_byte(2),
            },
        };
        let too_recent = ethlambda_types::beacon::containers::shared::AttestationData {
            slot: state.slot(),
            ..data
        };
        let first = committee_aggregate(data, 1, &[true, false], 1);
        let second = committee_aggregate(data, 0, &[false, true, true], 2);
        let packed = pack_attestations(
            &state,
            vec![
                first.clone(),
                second.clone(),
                committee_aggregate(too_recent, 0, &[true], 3),
            ],
        );

        assert_eq!(packed.len(), 1);
        let merged = &packed[0];
        // Committee 0's three bits, then committee 1's two.
        let bits: Vec<bool> = (0..merged.aggregation_bits.len())
            .map(|i| merged.aggregation_bits.get(i).unwrap())
            .collect();
        assert_eq!(bits, [false, true, true, true, false]);
        assert!(merged.committee_bits.get(0).unwrap() && merged.committee_bits.get(1).unwrap());
        assert_eq!(
            merged.signature,
            bls::aggregate(&[second.signature, first.signature]).unwrap()
        );
    }

    #[test]
    fn an_attestation_already_credited_on_chain_is_not_packed_again() {
        let mut state = state_to_build_on();
        let data = ethlambda_types::beacon::containers::shared::AttestationData {
            slot: state.slot() - 1,
            index: 0,
            beacon_block_root: Root::repeat_byte(1),
            source: state.current_justified_checkpoint(),
            target: ethlambda_types::beacon::containers::shared::Checkpoint {
                epoch: get_current_epoch(&state),
                root: Root::repeat_byte(2),
            },
        };
        let committee_len =
            crate::beacon::helpers::accessors::get_beacon_committee(&state, data.slot, 0)
                .unwrap()
                .len();
        let candidate = committee_aggregate(data, 0, &vec![true; committee_len], 1);
        assert_eq!(pack_attestations(&state, vec![candidate.clone()]).len(), 1);

        // Every validator credited for the current epoch, as if the same
        // votes had already been included.
        let BeaconState::Fulu(inner) = &mut state else {
            unreachable!("built as fulu")
        };
        for flags in inner.current_epoch_participation.iter_mut() {
            *flags = 0b111;
        }
        assert!(pack_attestations(&state, vec![candidate]).is_empty());
    }

    #[test]
    fn execution_requests_round_trip_through_the_request_list() {
        let requests = ExecutionRequests {
            withdrawals: vec![WithdrawalRequest {
                source_address: Default::default(),
                validator_pubkey: Default::default(),
                amount: 5,
            }]
            .try_into()
            .unwrap(),
            ..Default::default()
        };
        let list = stf::electra::get_execution_requests_list(&requests);
        assert_eq!(parse_execution_requests(&list).unwrap(), requests);
        assert_eq!(
            parse_execution_requests(&[]).unwrap(),
            ExecutionRequests::default()
        );
    }

    #[test]
    fn a_malformed_request_list_is_refused() {
        // Out of order.
        let withdrawal = vec![constants::WITHDRAWAL_REQUEST_TYPE, 1];
        let deposit = vec![constants::DEPOSIT_REQUEST_TYPE, 1];
        assert!(parse_execution_requests(&[withdrawal, deposit]).is_err());
        // Empty data, and an unknown type.
        assert!(parse_execution_requests(&[vec![constants::DEPOSIT_REQUEST_TYPE]]).is_err());
        assert!(parse_execution_requests(&[vec![0x7f, 0]]).is_err());
    }

    #[test]
    fn the_empty_sync_aggregate_signs_with_the_point_at_infinity() {
        let aggregate = empty_sync_aggregate();
        assert_eq!(aggregate.sync_committee_signature.0[0], 0xc0);
        assert!(
            aggregate.sync_committee_signature.0[1..]
                .iter()
                .all(|b| *b == 0)
        );
    }
}
