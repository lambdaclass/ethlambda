//! PQ block production (`specs/_features/pq/validator.md`): gloas's
//! self-build with PQ's shapes. The randao reveal is the proposer's VRF proof,
//! the self-build bid carries the empty `XMSSSignature()`, attestations carry
//! no signatures and the body one merged `proof` of theirs, the execution
//! requests are PQ's, and the block has no sync aggregate, payload
//! attestations, exits or credential changes.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use ethlambda_crypto::stark;
use ethlambda_storage::pools::PooledPqAggregate;

use crate::beacon::config::Config;
use crate::beacon::constants;
use crate::beacon::containers::{BeaconState, gloas, pq};
use crate::beacon::error::{Error, Result, verify};
use crate::beacon::gloas_block_production::GloasPayloadInputs;
use crate::beacon::helpers::accessors::{
    ActiveBalanceCache, CommitteeCache, PubkeyIndexCache, get_beacon_proposer_index,
    get_block_root, get_current_epoch, get_previous_epoch, get_randao_mix,
};
use crate::beacon::helpers::gloas::{get_attestation_participation_flag_indices, gloas_state_ref};
use crate::beacon::helpers::misc::compute_epoch_at_slot;
use crate::beacon::helpers::pq::{
    AggregateStatement, get_attestation_statements, get_attesting_indices,
};
use crate::beacon::preset;
use crate::beacon::primitives::{
    Bytes32, Epoch, HashTreeRoot as _, KzgCommitment, Root, ValidatorIndex,
};
use crate::beacon::stf;

/// `get_execution_requests` (PQ `validator.md`): the execution client's
/// EIP-7685 request list into PQ's `ExecutionRequests`, with its
/// preregistration and voluntary-exit request types. Strictly ascending
/// types and no empty element are checked, as gloas's are.
pub fn parse_pq_execution_requests(list: &[Vec<u8>]) -> Result<pq::ExecutionRequests> {
    let mut requests = pq::ExecutionRequests::default();
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
            constants::VALIDATOR_PREREGISTRATION_REQUEST_TYPE => {
                requests.validator_preregistrations =
                    libssz::SszDecode::from_ssz_bytes(data).map_err(malformed)?;
            }
            constants::BUILDER_PREREGISTRATION_REQUEST_TYPE => {
                requests.builder_preregistrations =
                    libssz::SszDecode::from_ssz_bytes(data).map_err(malformed)?;
            }
            constants::VOLUNTARY_EXIT_REQUEST_TYPE => {
                requests.voluntary_exits =
                    libssz::SszDecode::from_ssz_bytes(data).map_err(malformed)?;
            }
            _ => return Err(Error::SpecAssert("a known execution request type")),
        }
    }
    Ok(requests)
}

/// [`crate::beacon::gloas_block_production::gloas_payload_inputs`] on a PQ
/// state: the parent's requests, when building on its full payload, are PQ's
/// and applied by PQ's `apply_parent_execution_payload`.
pub fn pq_payload_inputs(
    state: &BeaconState,
    build_on_full: bool,
    parent_requests: &pq::ExecutionRequests,
    config: &Config,
) -> Result<GloasPayloadInputs> {
    let inner = gloas_state_ref(state, "pq_payload_inputs")?;
    let parent_bid = &inner.latest_execution_payload_bid;
    let (withdrawals, head_block_hash) = if build_on_full {
        let mut applied = state.clone();
        stf::pq::apply_parent_execution_payload(
            &mut applied,
            parent_requests,
            config,
            &ActiveBalanceCache::default(),
            &PubkeyIndexCache::default(),
        )?;
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

/// What a PQ block body carries beyond what this module derives from the
/// state.
#[derive(Debug, Clone)]
pub struct PqBlockInputs {
    /// The proposer's VRF proof for the slot.
    pub randao_reveal: pq::VrfProof,
    pub graffiti: Bytes32,
    pub attestations: Vec<pq::Attestation>,
    /// `stark.MergeProofs` of the attestations' aggregate proofs, in their
    /// order: empty with no attestations.
    pub proof: Vec<u8>,
    /// The parent envelope's requests when building on its full payload;
    /// empty otherwise.
    pub parent_execution_requests: pq::ExecutionRequests,
    pub execution_payload: gloas::ExecutionPayload,
    pub blob_kzg_commitments: Vec<KzgCommitment>,
    pub execution_requests: pq::ExecutionRequests,
}

/// A produced PQ block and the unsigned envelope that reveals its payload.
#[derive(Debug, Clone)]
pub struct PqProduced {
    pub block: pq::BeaconBlock,
    pub envelope: pq::ExecutionPayloadEnvelope,
}

/// The unsigned self-built PQ block for the slot `state` has been advanced
/// to, its state root computed by running PQ's `process_block` on a copy
/// (which also refuses a body the network would), and the unsigned envelope
/// for its payload, checked against that post-state but for its signature.
pub fn assemble_pq_block(
    state: &BeaconState,
    inputs: PqBlockInputs,
    config: &Config,
    options: stf::block::BlockProcessingOptions,
) -> Result<PqProduced> {
    verify(
        matches!(state, BeaconState::Pq(_)),
        "PQ block production runs on a PQ state",
    )?;
    let payload = &inputs.execution_payload;
    let bid = gloas::ExecutionPayloadBid {
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
    let proof = pq::AttestationProof::try_from(inputs.proof)
        .map_err(|_| Error::SpecAssert("the merged proof fits MAX_STARK_PROOF_SIZE"))?;
    let body = pq::BeaconBlockBody {
        randao_reveal: inputs.randao_reveal,
        eth1_data: state.eth1_data().clone(),
        graffiti: inputs.graffiti,
        attestations: inputs.attestations.into(),
        // Self-build: the empty `XMSSSignature()`, all zero bytes.
        signed_execution_payload_bid: pq::SignedExecutionPayloadBid {
            message: bid,
            signature: Default::default(),
        },
        parent_execution_requests: inputs.parent_execution_requests,
        proof,
        ..pq::BeaconBlockBody::empty()
    };
    let mut block = pq::BeaconBlock {
        slot: state.slot(),
        proposer_index: get_beacon_proposer_index(state)?,
        parent_root: state.latest_block_header().hash_tree_root(),
        state_root: Root::ZERO,
        body,
    };

    let mut post = state.clone();
    stf::pq::process_block(
        &mut post,
        &block,
        config,
        &CommitteeCache::default(),
        &ActiveBalanceCache::default(),
        &PubkeyIndexCache::default(),
        options,
    )?;
    post.apply_pending_mutations();
    block.state_root = post.hash_tree_root();

    let envelope = pq::ExecutionPayloadEnvelope {
        payload: inputs.execution_payload,
        execution_requests: inputs.execution_requests,
        builder_index: constants::BUILDER_INDEX_SELF_BUILD,
        beacon_block_root: block.hash_tree_root(),
        parent_beacon_block_root: block.parent_root,
    };
    check_envelope(&post, &block, &envelope, config)?;
    Ok(PqProduced { block, envelope })
}

/// `verify_execution_payload_envelope`'s conditions but the signature and
/// the engine, against `post`, the state after `block`.
fn check_envelope(
    post: &BeaconState,
    block: &pq::BeaconBlock,
    envelope: &pq::ExecutionPayloadEnvelope,
    config: &Config,
) -> Result<()> {
    let inner = gloas_state_ref(post, "assemble_pq_block")?;
    let bid = &inner.latest_execution_payload_bid;
    let payload = &envelope.payload;
    verify(
        envelope.beacon_block_root == block.hash_tree_root(),
        "the envelope names the block",
    )?;
    verify(
        payload.block_hash == bid.block_hash
            && payload.prev_randao == bid.prev_randao
            && payload.gas_limit == bid.gas_limit
            && envelope.execution_requests.hash_tree_root() == bid.execution_requests_root,
        "the envelope is the payload the bid commits to",
    )?;
    verify(
        payload.slot_number == post.slot(),
        "payload.slot_number == state.slot",
    )?;
    verify(
        payload.parent_hash == *inner.latest_block_hash,
        "payload.parent_hash == state.latest_block_hash",
    )?;
    verify(
        payload.timestamp == stf::bellatrix::compute_timestamp_at_slot(post, post.slot(), config),
        "payload.timestamp == compute_time_at_slot(state, state.slot)",
    )?;
    verify(
        payload.withdrawals.hash_tree_root() == inner.payload_expected_withdrawals.hash_tree_root(),
        "hash_tree_root(payload.withdrawals) == hash_tree_root(state.payload_expected_withdrawals)",
    )
}

// ---------------------------------------------------------------------------
// Attestations
// ---------------------------------------------------------------------------

/// What a PQ block packs from the pool: its attestations, and the network
/// aggregates behind them as the `(statements, proof)` children
/// `stark.MergeProofs` folds into the block's `proof`, in the order
/// `process_stark` reads the statements: the attestations', then each one's
/// committees ascending (PQ `validator.md`, "Proof").
#[derive(Debug, Default)]
pub struct PqPacked {
    pub attestations: Vec<pq::Attestation>,
    pub children: Vec<(Vec<AggregateStatement>, pq::AttestationProof)>,
}

impl PqPacked {
    /// The block's `proof`: `stark.MergeProofs` of the children. Empty with
    /// no attestations; one child is returned as it is, without proving.
    pub fn merge(&self) -> std::result::Result<Vec<u8>, stark::ProveError> {
        let children: Vec<(&[AggregateStatement], &[u8])> = self
            .children
            .iter()
            .map(|(statements, proof)| (statements.as_slice(), &proof[..]))
            .collect();
        stark::merge_proofs(&children)
    }
}

/// A participation flag a block would newly set: `(target epoch, attester,
/// flag index)`.
type Gain = (Epoch, ValidatorIndex, usize);

/// The network aggregates sharing one `AttestationData`, by committee, and
/// what packing them would newly credit, weighted.
#[derive(Debug, Default)]
struct DataGroup {
    committees: BTreeMap<u64, Arc<PooledPqAggregate>>,
    gains: BTreeMap<Gain, u64>,
}

/// Pick the attestations for a PQ block at `state`'s slot from the pool's
/// `candidates`, each a validated single-committee network aggregate.
///
/// Keeps only what `process_attestation` accepts at this slot (included at
/// least `MIN_ATTESTATION_INCLUSION_DELAY_PQ` after its own slot, targeting
/// the current or previous epoch, sourced from the justified checkpoint that
/// target implies, a payload vote of `0` or `1` and `0` for its own slot's
/// block), whose target root is this chain's, and whose committee here names
/// exactly the attesters it was validated with: a proof proves a fixed signer
/// set, so an aggregate read against another branch's committees would fail
/// `process_stark` for the whole block.
///
/// Aggregates sharing data become one attestation over their committees
/// (`compute_on_chain_aggregate`). Up to `MAX_ATTESTATIONS_PQ` are taken
/// greedily by the weight of participation flags they newly set, so one
/// already on chain earns nothing again.
pub fn select_pq_attestations(
    state: &BeaconState,
    candidates: Vec<Arc<PooledPqAggregate>>,
    committees: &CommitteeCache,
) -> Result<PqPacked> {
    let current_epoch = get_current_epoch(state);
    let previous_epoch = get_previous_epoch(state);
    let parent_slot = state.latest_block_header().slot;
    let (previous_participation, current_participation, _) = state.altair_validator_lists()?;

    let mut groups = BTreeMap::<Root, DataGroup>::new();
    for candidate in candidates {
        let data = &candidate.attestation.data;
        let target_epoch = data.target.epoch;
        let expected_source = if target_epoch == current_epoch {
            state.current_justified_checkpoint()
        } else {
            state.previous_justified_checkpoint()
        };
        let includable = data.slot + preset::MIN_ATTESTATION_INCLUSION_DELAY_PQ <= state.slot()
            && (target_epoch == current_epoch || target_epoch == previous_epoch)
            && target_epoch == compute_epoch_at_slot(data.slot)
            && data.source == expected_source
            && data.index < 2
            && get_block_root(state, target_epoch).is_ok_and(|root| root == data.target.root);
        if !includable {
            continue;
        }
        let same_signers = get_attesting_indices(state, &candidate.attestation, committees)
            .is_ok_and(|indices| indices == candidate.attesting_indices);
        if !same_signers {
            continue;
        }
        // Errs on a same-slot vote for the payload, which `process_attestation`
        // refuses.
        let Ok(flags) = get_attestation_participation_flag_indices(
            state,
            data,
            state.slot() - data.slot,
            parent_slot,
        ) else {
            continue;
        };
        let participation = if target_epoch == current_epoch {
            &current_participation
        } else {
            &previous_participation
        };
        let group = groups.entry(data.hash_tree_root()).or_default();
        for &index in &candidate.attesting_indices {
            let held = participation.get(index as usize).copied().unwrap_or(0);
            let balance = state.validator(index)?.effective_balance;
            for &flag in &flags {
                if held & (1 << flag) == 0 {
                    let weight = constants::PARTICIPATION_FLAG_WEIGHTS[flag];
                    group
                        .gains
                        .insert((target_epoch, index, flag), balance.saturating_mul(weight));
                }
            }
        }
        group
            .committees
            .insert(candidate.committee_index, candidate);
    }

    let mut packed = PqPacked::default();
    for group in take_greedily(groups) {
        let data = match group.committees.values().next() {
            Some(first) => first.attestation.data,
            None => continue,
        };
        let mut committee_bits = pq::CommitteeBits::default();
        let mut aggregation_bits = pq::AggregationBits::new();
        for (&committee, aggregate) in &group.committees {
            committee_bits
                .set(committee as usize, true)
                .map_err(|_| Error::SpecAssert("committee index < MAX_COMMITTEES_PER_SLOT_PQ"))?;
            let bits = &aggregate.attestation.aggregation_bits;
            for position in 0..bits.len() {
                aggregation_bits.push(bits.get(position).unwrap_or(false));
            }
            let statements = get_attestation_statements(state, &aggregate.attestation, committees)?;
            packed.children.push((statements, aggregate.proof.clone()));
        }
        packed.attestations.push(pq::Attestation {
            aggregation_bits,
            data,
            committee_bits,
        });
    }
    Ok(packed)
}

/// Up to `MAX_ATTESTATIONS_PQ` of `groups`, each time the one whose gains not
/// yet covered weigh the most, stopping when none adds anything.
fn take_greedily(mut groups: BTreeMap<Root, DataGroup>) -> Vec<DataGroup> {
    let mut covered = HashSet::<Gain>::new();
    let mut taken = Vec::new();
    while (taken.len() as u64) < preset::MAX_ATTESTATIONS_PQ {
        let score = |group: &DataGroup| {
            group
                .gains
                .iter()
                .filter(|(gain, _)| !covered.contains(*gain))
                .fold(0u64, |sum, (_, weight)| sum.saturating_add(*weight))
        };
        let Some((&root, best)) = groups.iter().max_by_key(|(_, group)| score(group)) else {
            break;
        };
        if score(best) == 0 {
            break;
        }
        let Some(group) = groups.remove(&root) else {
            break;
        };
        covered.extend(group.gains.keys().copied());
        taken.push(group);
    }
    taken
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::containers::shared::{AttestationData, Checkpoint};
    use crate::beacon::fork::ForkName;
    use crate::beacon::helpers::accessors::{CommitteeCacheExt as _, get_block_root_at_slot};
    use crate::beacon::helpers::pq::get_committee_indices;
    use crate::beacon::helpers::test_state::with_validators_at;
    use crate::beacon::primitives::Slot;

    /// A network aggregate of `committee` at `data`'s slot whose attesters
    /// are the members at `positions`, with a stand-in proof of `marker`
    /// bytes: selection never reads a proof, and the reference merge
    /// concatenates them.
    fn aggregate(
        state: &BeaconState,
        committees: &CommitteeCache,
        data: AttestationData,
        committee: u64,
        positions: &[usize],
        marker: u8,
    ) -> Arc<PooledPqAggregate> {
        let members = committees
            .committees(state, data.target.epoch)
            .committee(data.slot, committee)
            .unwrap()
            .to_vec();
        let mut aggregation_bits = pq::AggregationBits::with_length(members.len());
        for &position in positions {
            aggregation_bits.set(position, true).unwrap();
        }
        let mut committee_bits = pq::CommitteeBits::new();
        committee_bits.set(committee as usize, true).unwrap();
        let mut attesting_indices: Vec<ValidatorIndex> = positions
            .iter()
            .map(|&position| members[position])
            .collect();
        attesting_indices.sort_unstable();
        Arc::new(PooledPqAggregate {
            attestation: pq::Attestation {
                aggregation_bits,
                data,
                committee_bits,
            },
            committee_index: committee,
            attesting_indices,
            proof: vec![marker; 4].try_into().unwrap(),
        })
    }

    fn data_at(state: &BeaconState, slot: Slot) -> AttestationData {
        let epoch = compute_epoch_at_slot(slot);
        let source = if epoch == get_current_epoch(state) {
            state.current_justified_checkpoint()
        } else {
            state.previous_justified_checkpoint()
        };
        AttestationData {
            slot,
            index: 0,
            beacon_block_root: get_block_root_at_slot(state, slot).unwrap(),
            source,
            target: Checkpoint {
                epoch,
                root: get_block_root(state, epoch).unwrap(),
            },
        }
    }

    /// Two committees' aggregates of one vote, offered out of order, pack as
    /// one attestation: committee bits for both, the aggregation bits of
    /// committee 0 then committee 1, and the proofs in that same order, which
    /// is the order `process_stark` reads the statements in. An aggregate too
    /// fresh to include and one whose attesters this state's committee does
    /// not name are left out.
    #[test]
    fn aggregates_of_one_vote_pack_as_one_attestation_in_committee_order() {
        // Two committees per slot under the mainnet preset.
        let state = with_validators_at(ForkName::Pq, 2 * 32 * 128);
        let committees = CommitteeCache::default();
        let data_slot = state.slot() - preset::MIN_ATTESTATION_INCLUSION_DELAY_PQ;
        let data = data_at(&state, data_slot);
        let epoch_committees = committees.committees(&state, data.target.epoch);
        assert_eq!(epoch_committees.committees_per_slot(), 2);
        let committee_len = |index| epoch_committees.committee(data_slot, index).unwrap().len();
        let (len_zero, len_one) = (committee_len(0), committee_len(1));

        let second = aggregate(&state, &committees, data, 1, &[0, 1, 2], 2);
        let first = aggregate(&state, &committees, data, 0, &[0, 2], 1);
        let too_fresh = aggregate(
            &state,
            &committees,
            data_at(&state, state.slot() - 1),
            0,
            &[1],
            3,
        );
        let mut foreign = (*aggregate(
            &state,
            &committees,
            data_at(&state, data_slot - 1),
            0,
            &[0],
            4,
        ))
        .clone();
        foreign.attesting_indices = vec![foreign.attesting_indices[0] + 1];

        let candidates = vec![second, too_fresh, first, Arc::new(foreign)];
        let packed = select_pq_attestations(&state, candidates, &committees).unwrap();

        assert_eq!(packed.attestations.len(), 1);
        let attestation = &packed.attestations[0];
        assert_eq!(attestation.data, data);
        assert_eq!(
            get_committee_indices(&attestation.committee_bits),
            vec![0, 1]
        );
        let bits = &attestation.aggregation_bits;
        assert_eq!(bits.len(), len_zero + len_one);
        let set: Vec<usize> = (0..bits.len())
            .filter(|&i| bits.get(i) == Some(true))
            .collect();
        assert_eq!(set, vec![0, 2, len_zero, len_zero + 1, len_zero + 2]);

        let proofs: Vec<u8> = packed.children.iter().map(|(_, proof)| proof[0]).collect();
        assert_eq!(proofs, vec![1, 2]);
        let signers: Vec<usize> = packed
            .children
            .iter()
            .map(|(statements, _)| statements.iter().map(|s| s.pubkeys.len()).sum())
            .collect();
        assert_eq!(signers, vec![2, 3]);
        // The statements are the ones `process_stark` derives from the packed
        // attestation, in its order.
        let expected = get_attestation_statements(&state, attestation, &committees).unwrap();
        let packed_statements: Vec<_> = packed
            .children
            .iter()
            .flat_map(|(statements, _)| statements.iter().cloned())
            .collect();
        assert_eq!(packed_statements, expected);
        // The reference merge is the children's proofs concatenated.
        assert_eq!(packed.merge().unwrap(), [vec![1; 4], vec![2; 4]].concat());
    }

    /// An aggregate whose attesters already hold every flag it would set adds
    /// nothing and is not packed.
    #[test]
    fn an_aggregate_crediting_nobody_new_is_not_packed() {
        let mut state = with_validators_at(ForkName::Pq, 2 * 32 * 128);
        let committees = CommitteeCache::default();
        let data_slot = state.slot() - preset::MIN_ATTESTATION_INCLUSION_DELAY_PQ;
        let data = data_at(&state, data_slot);
        let candidate = aggregate(&state, &committees, data, 0, &[0], 1);
        let attester = candidate.attesting_indices[0];
        let before = select_pq_attestations(&state, vec![candidate.clone()], &committees).unwrap();
        assert_eq!(
            before.attestations.len(),
            1,
            "packed while it credits someone"
        );

        let current = data.target.epoch == get_current_epoch(&state);
        assert!(
            state
                .epoch_participation_mut(current)
                .unwrap()
                .set(attester as usize, 0b111)
        );
        state.apply_pending_mutations();
        let packed = select_pq_attestations(&state, vec![candidate], &committees).unwrap();
        assert!(packed.attestations.is_empty());
        assert!(packed.children.is_empty());
    }

    #[test]
    fn pq_request_types_parse_into_their_lists() {
        let exit = pq::VoluntaryExitRequest::default();
        let list = vec![
            [
                vec![constants::VOLUNTARY_EXIT_REQUEST_TYPE],
                libssz::SszEncode::to_ssz(&pq::VoluntaryExitRequests::from(vec![exit.clone()])),
            ]
            .concat(),
        ];
        let requests = parse_pq_execution_requests(&list).unwrap();
        assert_eq!(requests.voluntary_exits.len(), 1);
        assert!(requests.deposits.is_empty());
        // Round trip through the list builder.
        assert_eq!(stf::pq::get_execution_requests_list(&requests), list);
        // Out of order is refused.
        let twice = [list.clone(), list].concat();
        assert!(parse_pq_execution_requests(&twice).is_err());
    }
}
