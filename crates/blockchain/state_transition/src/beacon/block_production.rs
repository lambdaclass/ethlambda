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
        capella::{self, Withdrawal},
        deneb::ExecutionPayload,
        electra::{
            self, AggregationBits, Attestation, BeaconBlock, BeaconBlockBody, CommitteeBits,
            ConsolidationRequest, DepositRequest, ExecutionRequests, WithdrawalRequest,
        },
        shared::{ProposerSlashing, SignedVoluntaryExit},
    },
    preset,
    primitives::{
        BlsSignature, Bytes32, ExecutionBlockHash, HashTreeRoot as _, KzgCommitment, Root, Slot,
    },
    signing::compute_epoch_at_slot,
};
use libssz::SszDecode as _;
use libssz_types::SszList;

use super::bls;
use super::config::Config;
use super::error::{Error, Result, verify};
use super::helpers::accessors::{
    ActiveBalanceCache, CommitteeCache, get_beacon_proposer_index, get_block_root,
    get_block_root_at_slot, get_current_epoch, get_domain, get_previous_epoch, get_randao_mix,
};
use super::helpers::electra::{
    get_attesting_indices, get_indexed_attestation, is_valid_indexed_attestation,
};
use super::helpers::misc::compute_signing_root;
use super::helpers::predicates::is_slashable_validator;
use super::lean_boundary::lean_state_unreachable;
use super::stf::{self, ExecutionEngine};
use ethlambda_storage::pools::single_committee;

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
        BeaconState::Phase0(_)
        | BeaconState::Altair(_)
        | BeaconState::Bellatrix(_)
        | BeaconState::Capella(_)
        | BeaconState::Deneb(_) => {
            return Err(Error::SpecAssert("block production is electra and later"));
        }
        // Gloas builds its block around a builder's bid rather than an
        // execution payload the proposer requests, which nothing here models.
        BeaconState::Gloas(_) => {
            return Err(Error::SpecAssert("block production does not support gloas"));
        }
        BeaconState::Lean(_) => lean_state_unreachable("payload_inputs"),
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

/// `candidate` when it passes exactly the check `process_sync_aggregate` will
/// hold it to, else [`empty_sync_aggregate`].
///
/// `state` is the block's pre-state advanced to the block's slot. The
/// participants are `current_sync_committee`'s members by bits, signing the
/// block root at `state.slot - 1` under `DOMAIN_SYNC_COMMITTEE` at that slot's
/// epoch. A pooled aggregate can fail this when the proposer's parent is not
/// the root the committee signed, or when the head moved across a period: it
/// then costs the rewards, never the block.
pub fn verified_sync_aggregate(state: &BeaconState, candidate: SyncAggregate) -> SyncAggregate {
    let Ok((committee, _)) = state.sync_committees() else {
        return empty_sync_aggregate();
    };
    let participants: Vec<_> = committee
        .pubkeys
        .iter()
        .enumerate()
        .filter(|(position, _)| {
            candidate
                .sync_committee_bits
                .get(*position)
                .unwrap_or(false)
        })
        .map(|(_, pubkey)| *pubkey)
        .collect();
    let previous_slot = state.slot().saturating_sub(1);
    let Ok(block_root) = get_block_root_at_slot(state, previous_slot) else {
        return empty_sync_aggregate();
    };
    let domain = get_domain(
        state,
        constants::DOMAIN_SYNC_COMMITTEE,
        Some(compute_epoch_at_slot(previous_slot)),
    );
    let signing_root = compute_signing_root(block_root, domain);
    if bls::eth_fast_aggregate_verify(
        &participants,
        signing_root,
        &candidate.sync_committee_signature,
    ) {
        candidate
    } else {
        empty_sync_aggregate()
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
/// target implies. The target root must also be this state's block root at
/// the start of the target epoch. `process_attestation` does not check that,
/// but an attestation for another branch was aggregated against that branch's
/// committees, and its bits may name different validators here.
///
/// Of those, only candidates with at least one attester the state has not yet
/// credited for that epoch: an attestation already on chain earns nothing
/// again, and with room for only `MAX_ATTESTATIONS_ELECTRA` per block,
/// re-including it would crowd out ones that still count. Candidates voting on
/// the same `AttestationData` are merged into one electra `Attestation`
/// spanning their committees (EIP-7549's on-chain aggregation), ordered by how
/// many new attesters they bring, then newest first.
///
/// Each merged attestation's aggregate signature is then checked against
/// `state` in that order, and one that fails is dropped and the next taken in
/// its place. One invalid attestation fails `process_block` for the whole
/// block, and a candidate from gossip was verified against its own target
/// state, not this one. That is one signature check per packed attestation,
/// plus one per dropped one.
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
            && get_block_root(state, target_epoch).is_ok_and(|root| root == data.target.root)
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
    merged
        .into_iter()
        .map(|(_, attestation)| attestation)
        .filter(|attestation| {
            get_indexed_attestation(state, attestation, &committees)
                .is_ok_and(|indexed| is_valid_indexed_attestation(state, &indexed))
        })
        .take(preset::MAX_ATTESTATIONS_ELECTRA)
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

/// The four operation lists a block body carries besides attestations. Both
/// what the pool offers [`pack_operations`] and what it packs.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Operations {
    pub proposer_slashings: Vec<ProposerSlashing>,
    pub attester_slashings: Vec<electra::AttesterSlashing>,
    pub voluntary_exits: Vec<SignedVoluntaryExit>,
    pub bls_to_execution_changes: Vec<capella::SignedBLSToExecutionChange>,
}

impl Operations {
    /// Whether all four lists are empty.
    pub fn is_empty(&self) -> bool {
        self.proposer_slashings.is_empty()
            && self.attester_slashings.is_empty()
            && self.voluntary_exits.is_empty()
            && self.bls_to_execution_changes.is_empty()
    }
}

/// The candidates a block for `state`'s slot can carry, in the order
/// `process_operations` applies them, each kept only if its `process_*`
/// succeeds on a scratch copy of `state` with everything kept before it
/// already applied. That is what drops conflicting candidates, such as the
/// exit of a validator a packed slashing has just slashed.
///
/// Attestations sit between the slashings and the exits in the real order;
/// they change participation and credit the proposer's balance, and no later
/// operation's validity reads either, so they are left out of the scratch run.
///
/// `process_withdrawals` runs before `process_operations` in a real block but
/// not on the scratch state, so an exit whose pending partial withdrawal this
/// block pays out is dropped though the block would accept it. That only ever
/// drops valid exits, never admits invalid ones.
///
/// Attester slashings are ranked by how many validators each would slash on
/// the scratch state (after the proposer slashings), most first, and packed up
/// to `MAX_ATTESTER_SLASHINGS_ELECTRA`. Every list is capped at its preset
/// maximum.
pub fn pack_operations(state: &BeaconState, candidates: Operations, config: &Config) -> Operations {
    let mut scratch = state.clone();
    let proposer_slashings = pack_each(
        &mut scratch,
        candidates.proposer_slashings,
        preset::MAX_PROPOSER_SLASHINGS,
        config,
        stf::operations::process_proposer_slashing,
    );

    let epoch = get_current_epoch(&scratch);
    let mut ranked: Vec<(usize, electra::AttesterSlashing)> = candidates
        .attester_slashings
        .into_iter()
        .map(|slashing| (would_slash(&scratch, &slashing, epoch), slashing))
        .filter(|(count, _)| *count > 0)
        .collect();
    // Stable, so equally damaging slashings keep the order the pool offered.
    ranked.sort_by_key(|(count, _)| std::cmp::Reverse(*count));
    let attester_slashings = pack_each(
        &mut scratch,
        ranked.into_iter().map(|(_, slashing)| slashing).collect(),
        preset::MAX_ATTESTER_SLASHINGS_ELECTRA,
        config,
        stf::electra::process_attester_slashing,
    );

    let voluntary_exits = pack_each(
        &mut scratch,
        candidates.voluntary_exits,
        preset::MAX_VOLUNTARY_EXITS,
        config,
        stf::electra::process_voluntary_exit,
    );
    let bls_to_execution_changes = pack_each(
        &mut scratch,
        candidates.bls_to_execution_changes,
        preset::MAX_BLS_TO_EXECUTION_CHANGES,
        config,
        stf::electra::process_bls_to_execution_change,
    );
    Operations {
        proposer_slashings,
        attester_slashings,
        voluntary_exits,
        bls_to_execution_changes,
    }
}

/// The candidates `apply` accepts on `scratch`, in order, up to `max`; an
/// accepted one stays applied for the candidates after it.
///
/// Candidates are applied in place, with no copy to roll back to. That is safe
/// because every `process_*` used here runs all its checks (BLS verifies
/// included) before its first write: `process_proposer_slashing` checks before
/// `slash_validator`; electra's `process_attester_slashing` checks before its
/// loop, and its final `slashed_any` check fails only if nothing was written;
/// electra's `process_voluntary_exit` checks before `initiate_validator_exit`;
/// `process_bls_to_execution_change` writes last. A rejected candidate
/// therefore leaves the state untouched. Even a half-applied one could only
/// cost the caller's fallback, since `assemble_block` re-runs `process_block`
/// on a fresh copy of the state and never emits an invalid block.
fn pack_each<T>(
    scratch: &mut BeaconState,
    candidates: Vec<T>,
    max: usize,
    config: &Config,
    apply: impl Fn(&mut BeaconState, &T, &Config) -> Result<()>,
) -> Vec<T> {
    let mut packed = Vec::new();
    // Bounds the work if the pool is full of stale entries.
    for candidate in candidates.into_iter().take(4 * max) {
        if packed.len() == max {
            break;
        }
        if apply(scratch, &candidate, config).is_ok() {
            packed.push(candidate);
        }
    }
    packed
}

/// How many validators `slashing` would slash on `state` at `epoch`: those
/// attesting in both of its attestations that are still slashable.
fn would_slash(state: &BeaconState, slashing: &electra::AttesterSlashing, epoch: u64) -> usize {
    let second: std::collections::HashSet<_> = slashing
        .attestation_2
        .attesting_indices
        .iter()
        .copied()
        .collect();
    slashing
        .attestation_1
        .attesting_indices
        .iter()
        .filter(|index| second.contains(*index))
        .filter(|&&index| {
            state
                .validator(index)
                .is_ok_and(|validator| is_slashable_validator(validator, epoch))
        })
        .count()
}

/// What a block body carries beyond what this module derives from the state.
#[derive(Debug, Clone)]
pub struct BlockInputs {
    pub randao_reveal: BlsSignature,
    pub graffiti: Bytes32,
    pub attestations: Vec<Attestation>,
    /// Slashings, exits and credential changes, as [`pack_operations`] returns
    /// them.
    pub operations: Operations,
    pub execution_payload: ExecutionPayload,
    pub blob_kzg_commitments: Vec<KzgCommitment>,
    pub execution_requests: ExecutionRequests,
    /// The block's sync aggregate: [`empty_sync_aggregate`], or what
    /// [`verified_sync_aggregate`] vouched for.
    pub sync_aggregate: SyncAggregate,
}

/// The unsigned block for the slot `state` has been advanced to, with its
/// state root computed.
///
/// The body votes the state's own `eth1_data` and carries no deposits (the
/// deposit contract's log has been replaced by EIP-6110's requests), the
/// slashings, exits and credential changes in `inputs.operations`, and the
/// sync aggregate it is given. The block is run through `process_block` on a copy of
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
        proposer_slashings: inputs
            .operations
            .proposer_slashings
            .try_into()
            .map_err(|_| Error::SpecAssert("len(proposer_slashings) <= MAX_PROPOSER_SLASHINGS"))?,
        attester_slashings: inputs
            .operations
            .attester_slashings
            .try_into()
            .map_err(|_| {
                Error::SpecAssert("len(attester_slashings) <= MAX_ATTESTER_SLASHINGS_ELECTRA")
            })?,
        voluntary_exits: inputs
            .operations
            .voluntary_exits
            .try_into()
            .map_err(|_| Error::SpecAssert("len(voluntary_exits) <= MAX_VOLUNTARY_EXITS"))?,
        bls_to_execution_changes: inputs
            .operations
            .bls_to_execution_changes
            .try_into()
            .map_err(|_| {
                Error::SpecAssert("len(bls_to_execution_changes) <= MAX_BLS_TO_EXECUTION_CHANGES")
            })?,
        sync_aggregate: inputs.sync_aggregate,
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
        BeaconState::Phase0(_)
        | BeaconState::Altair(_)
        | BeaconState::Bellatrix(_)
        | BeaconState::Capella(_)
        | BeaconState::Deneb(_) => {
            return Err(Error::SpecAssert("block production is electra and later"));
        }
        BeaconState::Gloas(_) => {
            return Err(Error::SpecAssert("block production does not support gloas"));
        }
        BeaconState::Lean(_) => lean_state_unreachable("assemble_block"),
    };
    let mut post = state.clone();
    stf::block::process_block(
        &mut post,
        &wrapped,
        config,
        &ExecutionEngine::valid(),
        &CommitteeCache::default(),
        &ActiveBalanceCache::default(),
    )?;
    // Fold the block's writes into their trees first, so the root is computed
    // on (and cached in) the state's own nodes rather than a throwaway copy,
    // as `state_transition` does before it checks a block's state root.
    post.apply_pending_mutations();
    block.state_root = post.hash_tree_root();
    Ok(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::ForkName;
    use crate::beacon::helpers::accessors::{get_beacon_committee, get_domain};
    use crate::beacon::helpers::fulu::initialize_proposer_lookahead;
    use crate::beacon::helpers::misc::compute_domain;
    use crate::beacon::helpers::misc::compute_signing_root;
    use crate::beacon::helpers::test_state::{sign_for, with_signing_validators_at};
    use ethlambda_types::beacon::containers::shared::{
        AttestationData, BeaconBlockHeader, Checkpoint, SignedBeaconBlockHeader, VoluntaryExit,
    };

    /// A fulu state one epoch in, its lookahead and sync committee filled from
    /// its real registry (the builder leaves both as placeholders), advanced one
    /// slot so a block can be built on it.
    fn state_to_build_on() -> BeaconState {
        state_to_build_on_with(64)
    }

    /// [`state_to_build_on`] with `validators` in the registry. Mainnet's
    /// preset splits a slot into more than one committee only from
    /// `2 * SLOTS_PER_EPOCH * TARGET_COMMITTEE_SIZE` active validators.
    fn state_to_build_on_with(validators: usize) -> BeaconState {
        let mut state = with_signing_validators_at(ForkName::Fulu, validators);
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
            sync_aggregate: empty_sync_aggregate(),
            randao_reveal: randao_reveal(&state),
            graffiti: Bytes32::repeat_byte(7),
            attestations: Vec::new(),
            operations: Operations::default(),
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
            &ActiveBalanceCache::default(),
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
            sync_aggregate: empty_sync_aggregate(),
            randao_reveal: randao_reveal(&state),
            graffiti: Bytes32::ZERO,
            attestations: Vec::new(),
            operations: Operations::default(),
            execution_payload: payload,
            blob_kzg_commitments: Vec::new(),
            execution_requests: ExecutionRequests::default(),
        };
        assert!(assemble_block(&state, inputs, &Config::mainnet()).is_err());
    }

    /// An attestation at `slot` voting for this state's own chain: sourced from
    /// its current justified checkpoint, targeting its current epoch at the
    /// state's block root there.
    fn attestation_data(state: &BeaconState, slot: Slot) -> AttestationData {
        let epoch = get_current_epoch(state);
        AttestationData {
            slot,
            index: 0,
            beacon_block_root: Root::repeat_byte(1),
            source: state.current_justified_checkpoint(),
            target: Checkpoint {
                epoch,
                root: get_block_root(state, epoch).unwrap(),
            },
        }
    }

    /// A single-committee aggregate over `data` from `committee`, with the
    /// members at `positions` set and signed by exactly those members, so it
    /// verifies against `state`.
    fn committee_aggregate(
        state: &BeaconState,
        data: AttestationData,
        committee: u64,
        positions: &[usize],
    ) -> Attestation {
        let members = get_beacon_committee(state, data.slot, committee).unwrap();
        let domain = get_domain(
            state,
            constants::DOMAIN_BEACON_ATTESTER,
            Some(data.target.epoch),
        );
        let signing_root = compute_signing_root(data.hash_tree_root(), domain);
        let mut aggregation_bits = AggregationBits::with_length(members.len()).unwrap();
        let signatures: Vec<_> = positions
            .iter()
            .map(|&position| {
                aggregation_bits.set(position, true).unwrap();
                sign_for(members[position] as usize, signing_root)
            })
            .collect();
        let mut committee_bits = CommitteeBits::default();
        committee_bits.set(committee as usize, true).unwrap();
        Attestation {
            aggregation_bits,
            data,
            signature: bls::aggregate(&signatures).unwrap(),
            committee_bits,
        }
    }

    #[test]
    fn committees_voting_alike_are_merged_and_the_too_recent_left_out() {
        // Enough validators for at least two committees a slot: exactly two
        // under mainnet's preset, more under minimal's smaller committees. The
        // test only uses committees 0 and 1.
        let state = state_to_build_on_with(8192);
        let committees_per_slot = crate::beacon::helpers::accessors::get_committee_count_per_slot(
            &state,
            get_current_epoch(&state),
        );
        assert!(committees_per_slot >= 2, "got {committees_per_slot}");
        let data = attestation_data(&state, state.slot() - 1);
        let too_recent = AttestationData {
            slot: state.slot(),
            ..data
        };
        let first = committee_aggregate(&state, data, 1, &[0]);
        let second = committee_aggregate(&state, data, 0, &[1, 2]);
        let committee_0_len = second.aggregation_bits.len();
        let packed = pack_attestations(
            &state,
            vec![
                first.clone(),
                second.clone(),
                committee_aggregate(&state, too_recent, 0, &[0]),
            ],
        );

        assert_eq!(packed.len(), 1);
        let merged = &packed[0];
        // Committee 0's bits, then committee 1's.
        let set: Vec<usize> = (0..merged.aggregation_bits.len())
            .filter(|&i| merged.aggregation_bits.get(i).unwrap())
            .collect();
        assert_eq!(set, [1, 2, committee_0_len]);
        assert!(merged.committee_bits.get(0).unwrap() && merged.committee_bits.get(1).unwrap());
        assert_eq!(
            merged.signature,
            bls::aggregate(&[second.signature, first.signature]).unwrap()
        );
    }

    #[test]
    fn an_attestation_already_credited_on_chain_is_not_packed_again() {
        let mut state = state_to_build_on();
        let data = attestation_data(&state, state.slot() - 1);
        let committee_len = get_beacon_committee(&state, data.slot, 0).unwrap().len();
        let everyone: Vec<usize> = (0..committee_len).collect();
        let candidate = committee_aggregate(&state, data, 0, &everyone);
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

    /// A vote for another branch was aggregated against that branch's
    /// committees, so its bits cannot be trusted to name the same validators
    /// on this one, however valid it was where it came from.
    #[test]
    fn an_attestation_targeting_another_branch_is_not_packed() {
        let state = state_to_build_on();
        let mut data = attestation_data(&state, state.slot() - 1);
        data.target.root = Root::repeat_byte(2);
        let candidate = committee_aggregate(&state, data, 0, &[0]);
        assert!(pack_attestations(&state, vec![candidate]).is_empty());
    }

    /// One attestation whose signature does not verify against this state
    /// would fail the whole block, so it is dropped and the rest are packed.
    #[test]
    fn an_attestation_that_does_not_verify_is_dropped_and_the_rest_packed() {
        let state = state_to_build_on();
        let valid =
            committee_aggregate(&state, attestation_data(&state, state.slot() - 1), 0, &[0]);

        // Different data, so the two are not merged, signed by the wrong
        // member of the committee.
        let mut forged_data = attestation_data(&state, state.slot() - 1);
        forged_data.beacon_block_root = Root::repeat_byte(3);
        let mut forged = committee_aggregate(&state, forged_data, 0, &[0]);
        forged.signature = committee_aggregate(&state, forged_data, 0, &[1]).signature;

        let packed = pack_attestations(&state, vec![forged, valid.clone()]);
        assert_eq!(packed, vec![valid]);
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

    /// A config under which a validator active since genesis may exit at once.
    fn config_allowing_young_exits() -> Config {
        let mut config = Config::mainnet();
        config.shard_committee_period = 0;
        config
    }

    fn signed_exit(state: &BeaconState, index: u64, sign: bool) -> SignedVoluntaryExit {
        let message = VoluntaryExit {
            epoch: 0,
            validator_index: index,
        };
        let domain = compute_domain(
            constants::DOMAIN_VOLUNTARY_EXIT,
            Config::mainnet().capella_fork_version,
            state.genesis_validators_root(),
        );
        let signing_root = compute_signing_root(message.hash_tree_root(), domain);
        SignedVoluntaryExit {
            message,
            signature: if sign {
                sign_for(index as usize, signing_root)
            } else {
                BlsSignature::default()
            },
        }
    }

    fn proposer_slashing(state: &BeaconState, index: u64) -> ProposerSlashing {
        let sign_header = |state_root: u8| {
            let message = BeaconBlockHeader {
                slot: state.slot(),
                proposer_index: index,
                state_root: Root::repeat_byte(state_root),
                ..Default::default()
            };
            let domain = get_domain(
                state,
                constants::DOMAIN_BEACON_PROPOSER,
                Some(compute_epoch_at_slot(message.slot)),
            );
            let signing_root = compute_signing_root(message.hash_tree_root(), domain);
            SignedBeaconBlockHeader {
                message,
                signature: sign_for(index as usize, signing_root),
            }
        };
        ProposerSlashing {
            signed_header_1: sign_header(1),
            signed_header_2: sign_header(2),
        }
    }

    /// A double vote by `indices`: two attestations with the same target epoch
    /// and different data, each signed by all of them.
    fn attester_slashing(state: &BeaconState, indices: &[u64]) -> electra::AttesterSlashing {
        let indexed = |beacon_block_root: u8| {
            let data = AttestationData {
                beacon_block_root: Root::repeat_byte(beacon_block_root),
                ..attestation_data(state, state.slot() - 1)
            };
            let domain = get_domain(
                state,
                constants::DOMAIN_BEACON_ATTESTER,
                Some(data.target.epoch),
            );
            let signing_root = compute_signing_root(data.hash_tree_root(), domain);
            let signatures: Vec<_> = indices
                .iter()
                .map(|&index| sign_for(index as usize, signing_root))
                .collect();
            electra::IndexedAttestation {
                attesting_indices: indices.to_vec().try_into().unwrap(),
                data,
                signature: bls::aggregate(&signatures).unwrap(),
            }
        };
        electra::AttesterSlashing {
            attestation_1: indexed(1),
            attestation_2: indexed(2),
        }
    }

    fn slashed_indices(slashing: &electra::AttesterSlashing) -> Vec<u64> {
        slashing
            .attestation_1
            .attesting_indices
            .iter()
            .copied()
            .filter(|index| slashing.attestation_2.attesting_indices.contains(index))
            .collect()
    }

    #[test]
    fn an_exit_by_a_validator_slashed_in_the_same_block_is_dropped() {
        let state = state_to_build_on();
        let config = config_allowing_young_exits();
        let candidates = Operations {
            proposer_slashings: vec![proposer_slashing(&state, 5)],
            voluntary_exits: vec![signed_exit(&state, 5, true)],
            ..Default::default()
        };
        let packed = pack_operations(&state, candidates, &config);
        assert_eq!(packed.proposer_slashings.len(), 1);
        assert!(packed.voluntary_exits.is_empty());
    }

    #[test]
    fn the_attester_slashing_that_slashes_the_most_validators_is_packed() {
        let state = state_to_build_on();
        let candidates = Operations {
            attester_slashings: vec![
                attester_slashing(&state, &[3]),
                attester_slashing(&state, &[1, 2]),
            ],
            ..Default::default()
        };
        let packed = pack_operations(&state, candidates, &Config::mainnet());
        assert_eq!(packed.attester_slashings.len(), 1);
        assert_eq!(slashed_indices(&packed.attester_slashings[0]), vec![1, 2]);
    }

    #[test]
    fn attester_slashings_are_ranked_after_the_proposer_slashings() {
        let state = state_to_build_on();
        let candidates = Operations {
            proposer_slashings: vec![proposer_slashing(&state, 1), proposer_slashing(&state, 2)],
            attester_slashings: vec![
                attester_slashing(&state, &[1, 2, 3]),
                attester_slashing(&state, &[4, 5]),
            ],
            ..Default::default()
        };
        let packed = pack_operations(&state, candidates, &Config::mainnet());
        assert_eq!(packed.proposer_slashings.len(), 2);
        assert_eq!(packed.attester_slashings.len(), 1);
        assert_eq!(slashed_indices(&packed.attester_slashings[0]), vec![4, 5]);
    }

    #[test]
    fn exits_are_capped_at_max_voluntary_exits() {
        let state = state_to_build_on();
        let exits = (0..=preset::MAX_VOLUNTARY_EXITS as u64)
            .map(|index| signed_exit(&state, index, true))
            .collect();
        let candidates = Operations {
            voluntary_exits: exits,
            ..Default::default()
        };
        let packed = pack_operations(&state, candidates, &config_allowing_young_exits());
        assert_eq!(packed.voluntary_exits.len(), preset::MAX_VOLUNTARY_EXITS);
    }

    #[test]
    fn an_invalid_candidate_is_skipped_not_fatal() {
        let state = state_to_build_on();
        let candidates = Operations {
            voluntary_exits: vec![signed_exit(&state, 1, false), signed_exit(&state, 2, true)],
            ..Default::default()
        };
        let packed = pack_operations(&state, candidates, &config_allowing_young_exits());
        assert_eq!(packed.voluntary_exits.len(), 1);
        assert_eq!(packed.voluntary_exits[0].message.validator_index, 2);
    }

    #[test]
    fn assemble_block_carries_packed_operations() {
        let state = state_to_build_on();
        let config = config_allowing_young_exits();
        let operations = pack_operations(
            &state,
            Operations {
                voluntary_exits: vec![signed_exit(&state, 4, true)],
                ..Default::default()
            },
            &config,
        );
        assert!(!operations.is_empty());
        let inputs = BlockInputs {
            randao_reveal: randao_reveal(&state),
            graffiti: Bytes32::ZERO,
            attestations: Vec::new(),
            operations,
            execution_payload: payload_for(&state),
            blob_kzg_commitments: Vec::new(),
            sync_aggregate: empty_sync_aggregate(),
            execution_requests: ExecutionRequests::default(),
        };
        let block = assemble_block(&state, inputs, &config).unwrap();
        assert_eq!(block.body.voluntary_exits.len(), 1);
        assert_eq!(block.body.voluntary_exits[0].message.validator_index, 4);
    }

    /// A pool holding messages from `positions` of the committee, signed the way
    /// `process_sync_aggregate` will check them (over the block root at
    /// `state.slot - 1`, under the state's own domain), plus that root.
    fn pooled_aggregate(
        state: &BeaconState,
        signed_root: Option<Root>,
        positions: &[usize],
    ) -> (SyncAggregate, Root) {
        use crate::beacon::sync_committee_pool::SyncCommitteePool;
        use ethlambda_types::beacon::containers::altair::{
            SYNC_SUBCOMMITTEE_SIZE, SyncCommitteeMessage,
        };

        let previous_slot = state.slot() - 1;
        let parent_root = get_block_root_at_slot(state, previous_slot).unwrap();
        let root = signed_root.unwrap_or(parent_root);
        let domain = get_domain(
            state,
            constants::DOMAIN_SYNC_COMMITTEE,
            Some(compute_epoch_at_slot(previous_slot)),
        );
        let signing_root = compute_signing_root(root, domain);
        let (committee, _) = state.sync_committees().unwrap();
        let mut pool = SyncCommitteePool::default();
        for &position in positions {
            let pubkey = committee.pubkeys[position];
            let index = (0..64)
                .find(|&index| state.validator(index).unwrap().pubkey == pubkey)
                .expect("the committee is drawn from the registry");
            let message = SyncCommitteeMessage {
                slot: previous_slot,
                beacon_block_root: parent_root,
                validator_index: index,
                signature: sign_for(index as usize, signing_root),
            };
            let seats = [(
                (position / SYNC_SUBCOMMITTEE_SIZE) as u64,
                position % SYNC_SUBCOMMITTEE_SIZE,
            )];
            pool.insert_message(&message, &seats);
        }
        (
            pool.sync_aggregate(previous_slot, parent_root)
                .expect("something was pooled"),
            parent_root,
        )
    }

    #[test]
    fn a_pooled_sync_aggregate_passes_assemble_block() {
        let state = state_to_build_on();
        let (candidate, _) = pooled_aggregate(&state, None, &[0, 1, 5]);
        let verified = verified_sync_aggregate(&state, candidate.clone());
        assert_eq!(verified, candidate);
        assert!(verified.sync_committee_bits.count_ones() >= 3);
        let inputs = BlockInputs {
            randao_reveal: randao_reveal(&state),
            graffiti: Bytes32::repeat_byte(7),
            attestations: Vec::new(),
            operations: Operations::default(),
            execution_payload: payload_for(&state),
            blob_kzg_commitments: Vec::new(),
            execution_requests: ExecutionRequests::default(),
            sync_aggregate: verified.clone(),
        };
        let block = assemble_block(&state, inputs, &Config::mainnet()).unwrap();
        assert_eq!(block.body.sync_aggregate, verified);
    }

    #[test]
    fn a_sync_aggregate_over_the_wrong_root_is_replaced_by_the_empty_one() {
        let state = state_to_build_on();
        let (wrong, _) = pooled_aggregate(&state, Some(Root::repeat_byte(1)), &[0, 1]);
        assert_eq!(
            verified_sync_aggregate(&state, wrong),
            empty_sync_aggregate()
        );
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
