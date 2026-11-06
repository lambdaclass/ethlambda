//! Tests for EIP-8453's fork upgrade, slot processing and block processing,
//! including whole signed blocks run through `state_transition`.

use super::*;
use crate::beacon::containers::SignedBeaconBlock;
use crate::beacon::fork::ForkName;
use crate::beacon::helpers::accessors::{CommitteeCache, get_block_root_at_slot, get_randao_mix};
use crate::beacon::helpers::eip8453::get_attestation_committee;
use crate::beacon::helpers::test_state;
use crate::beacon::primitives::{BlsSignature, Bytes32, DomainType, Epoch, Slot};
use crate::beacon::stf::{self, ExecutionEngine};

fn config() -> Config {
    Config::active().with_fork_epoch(ForkName::Eip8453, 1)
}

fn inner(state: &BeaconState) -> &eip8453::BeaconState {
    eip8453_state(state, "test").unwrap()
}

fn inner_mut(state: &mut BeaconState) -> &mut eip8453::BeaconState {
    eip8453_state_mut(state, "test").unwrap()
}

/// An EIP-8453 state a block can be built on: real keys, every sync
/// committee seat held by a registered key, and the parent's payload not
/// delivered (its bid's block hash differs from `latest_block_hash`), so a
/// self-built bid needs no execution requests.
fn chain_state(count: usize) -> BeaconState {
    let mut state = test_state::with_signing_validators_at(ForkName::Eip8453, count);
    let pubkeys: Vec<_> = state.iter_validators().map(|v| v.pubkey).collect();
    let inner = inner_mut(&mut state);
    for (seat, pubkey) in inner.current_sync_committee.pubkeys.iter_mut().enumerate() {
        *pubkey = pubkeys[seat % pubkeys.len()];
    }
    inner.next_sync_committee = inner.current_sync_committee.clone();
    inner.latest_execution_payload_bid.block_hash = Bytes32::repeat_byte(0xaa);
    state
}

fn sign(
    state: &BeaconState,
    index: ValidatorIndex,
    root: Root,
    domain_type: DomainType,
    epoch: Epoch,
) -> BlsSignature {
    let domain = get_domain(state, domain_type, Some(epoch));
    test_state::sign_for(index as usize, compute_signing_root(root, domain))
}

fn attestation_data(
    target: eip8453::HeightCheckpoint,
    timeout: bool,
    finality: eip8453::HeightCheckpoint,
) -> eip8453::AttestationData {
    eip8453::AttestationData {
        target,
        timeout,
        finality,
    }
}

/// An aggregate of `data` from every member of the given committees of
/// `epoch` that `include` admits, signed by each.
fn aggregate(
    state: &BeaconState,
    data: eip8453::AttestationData,
    epoch: Epoch,
    include: impl Fn(ValidatorIndex) -> bool,
) -> eip8453::Attestation {
    let mut committee_bits = eip8453::AttestationCommitteeBits::new();
    let mut members = Vec::new();
    for index in 0..preset::ATTESTATION_COMMITTEES_PER_ROUND as u64 {
        let committee = get_attestation_committee(state, epoch, index).unwrap();
        if committee.is_empty() {
            continue;
        }
        committee_bits.set(index as usize, true).unwrap();
        members.extend(committee.iter().copied());
    }
    let mut aggregation_bits = eip8453::AggregationBits::with_length(members.len());
    let mut signatures = Vec::new();
    for (position, member) in members.iter().enumerate() {
        if include(*member) {
            aggregation_bits.set(position, true).unwrap();
            signatures.push(sign(
                state,
                *member,
                data.hash_tree_root(),
                constants::DOMAIN_FINALITY_ATTESTER,
                epoch,
            ));
        }
    }
    eip8453::Attestation {
        aggregation_bits,
        data,
        signature: bls::aggregate(&signatures).unwrap(),
        committee_bits,
        epoch,
    }
}

/// A head vote for `slot`'s `root` by every distinct member of its committee,
/// with `support` in every support bit.
fn head_vote(
    state: &BeaconState,
    slot: Slot,
    root: Root,
    payload_status: u8,
    support: bool,
    config: &Config,
) -> (eip8453::HeadVote, eip8453::HeadVoteSupportBits) {
    let committee = get_head_vote_committee(state, slot, config).unwrap();
    let mut voters: Vec<ValidatorIndex> = committee.to_vec();
    voters.sort_unstable();
    voters.dedup();
    let data = eip8453::HeadVoteData {
        slot,
        beacon_block_root: root,
        payload_status,
    };
    let epoch = compute_epoch_at_slot(slot);
    let signatures: Vec<_> = voters
        .iter()
        .map(|voter| {
            sign(
                state,
                *voter,
                data.hash_tree_root(),
                constants::DOMAIN_HEAD_VOTE,
                epoch,
            )
        })
        .collect();
    let mut support_bits = eip8453::HeadVoteSupportBits::with_length(voters.len());
    for bit in 0..voters.len() {
        support_bits.set(bit, support).unwrap();
    }
    let vote = eip8453::HeadVote {
        voter_indices: voters.try_into().unwrap(),
        data,
        signature: bls::aggregate(&signatures).unwrap(),
    };
    (vote, support_bits)
}

/// A signed block at `pre.slot()` (already advanced to it) carrying `body`'s
/// operations, with a self-built bid, an empty sync aggregate, the proposer's
/// RANDAO reveal, and the post-state's root.
fn signed_block(
    pre: &BeaconState,
    mut body: eip8453::BeaconBlockBody,
    config: &Config,
) -> SignedBeaconBlock {
    let slot = pre.slot();
    let epoch = compute_epoch_at_slot(slot);
    let proposer_index = get_beacon_proposer_index(pre).unwrap();

    body.randao_reveal = sign(
        pre,
        proposer_index,
        epoch.hash_tree_root(),
        constants::DOMAIN_RANDAO,
        epoch,
    );
    let bid = &mut body.signed_execution_payload_bid;
    bid.message.builder_index = constants::BUILDER_INDEX_SELF_BUILD;
    bid.message.value = 0;
    bid.message.slot = slot;
    bid.message.parent_block_hash = *pre.latest_block_hash().unwrap();
    bid.message.block_hash = Bytes32::repeat_byte(slot as u8 + 1);
    bid.message.parent_block_root = get_block_root_at_slot(pre, slot - 1).unwrap();
    bid.message.prev_randao = get_randao_mix(pre, epoch);
    bid.signature = BlsSignature(bls::G2_POINT_AT_INFINITY);
    body.sync_aggregate.sync_committee_signature = BlsSignature(bls::G2_POINT_AT_INFINITY);

    let mut block = eip8453::BeaconBlock {
        slot,
        proposer_index,
        parent_root: pre.latest_block_header().hash_tree_root(),
        state_root: Root::ZERO,
        body,
    };
    let mut post = pre.clone();
    let unsigned = SignedBeaconBlock::Eip8453(eip8453::SignedBeaconBlock {
        message: block.clone(),
        signature: BlsSignature::default(),
    });
    super::super::block::process_block(
        &mut post,
        &unsigned,
        config,
        &ExecutionEngine::valid(),
        &CommitteeCache::default(),
        &ActiveBalanceCache::default(),
        BlockProcessingOptions::default(),
    )
    .unwrap();
    post.apply_pending_mutations();
    block.state_root = post.hash_tree_root();

    let signature = sign(
        pre,
        proposer_index,
        block.hash_tree_root(),
        constants::DOMAIN_BEACON_PROPOSER,
        epoch,
    );
    SignedBeaconBlock::Eip8453(eip8453::SignedBeaconBlock {
        message: block,
        signature,
    })
}

fn transition(state: &mut BeaconState, block: &SignedBeaconBlock, config: &Config) -> Result<()> {
    stf::state_transition(
        state,
        block,
        true,
        config,
        &ExecutionEngine::valid(),
        &CommitteeCache::default(),
        &ActiveBalanceCache::default(),
    )
}

// ---------------------------------------------------------------------------
// Fork upgrade and slot processing
// ---------------------------------------------------------------------------

#[test]
fn upgrade_to_eip8453_starts_the_finality_gadget_from_the_finalized_casper_checkpoint() {
    let mut pre = test_state::with_validators_at(ForkName::Heze, 6);
    let finalized = crate::beacon::containers::Checkpoint {
        epoch: 1,
        root: Root::repeat_byte(7),
    };
    *pre.finalized_checkpoint_mut().unwrap() = finalized;
    pre.latest_block_header_mut().slot = 5;
    pre.fork_mut().current_version = [8, 0, 0, 0];
    let header_root = pre.latest_block_header().hash_tree_root();
    let config = config();

    let post = crate::beacon::upgrade::upgrade_state(&pre, ForkName::Eip8453, &config).unwrap();
    let inner = inner(&post);

    assert_eq!(post.fork_name(), ForkName::Eip8453);
    assert_eq!(inner.fork.previous_version, [8, 0, 0, 0]);
    assert_eq!(inner.fork.current_version, config.eip8453_fork_version);
    assert_eq!(inner.fork.epoch, compute_epoch_at_slot(pre.slot()));
    assert_eq!(
        inner.target_checkpoint,
        eip8453::HeightCheckpoint {
            height: 1,
            root: header_root
        }
    );
    let at_zero = eip8453::HeightCheckpoint {
        height: 0,
        root: finalized.root,
    };
    assert_eq!(inner.justified_checkpoint, at_zero);
    assert_eq!(inner.finalized_checkpoint, at_zero);
    assert_eq!(inner.target_slot, 5);
    assert_eq!(inner.finalized_slot, preset::SLOTS_PER_EPOCH);
    assert_eq!(inner.target_participation.to_vec(), vec![false; 6]);
    assert_eq!(inner.progress_participation.to_vec(), vec![false; 6]);
    assert_eq!(inner.round_participation.to_vec(), vec![0; 6]);
    assert!(inner.pending_finality.is_empty());
    assert_eq!(
        inner.head_vote_participation,
        eip8453::empty_head_vote_participation()
    );
    assert_eq!(
        inner.head_vote_committee_window,
        crate::beacon::helpers::eip8453::initialize_head_vote_committee_window(&post).unwrap()
    );
    // Everything heze carried over is unchanged.
    assert_eq!(post.validators_root(), pre.validators_root());
    assert_eq!(post.ptc_window().unwrap(), pre.ptc_window().unwrap());
    // Only a heze state upgrades.
    assert!(crate::beacon::upgrade::upgrade_to_eip8453(&post, &config).is_err());
}

#[test]
fn process_slot_fills_an_empty_target_root_with_the_latest_block_root() {
    let mut state = test_state::with_validators_at(ForkName::Eip8453, 4);
    inner_mut(&mut state).target_checkpoint.root = Root::ZERO;
    stf::process_slot(&mut state).unwrap();
    let block_root = state.latest_block_header().hash_tree_root();
    assert_eq!(inner(&state).target_checkpoint.root, block_root);

    // A root already set is left alone.
    inner_mut(&mut state).target_checkpoint.root = Root::repeat_byte(3);
    *state.slot_mut() += 1;
    stf::process_slot(&mut state).unwrap();
    assert_eq!(inner(&state).target_checkpoint.root, Root::repeat_byte(3));
}

/// The fork transition, then empty slots across a round boundary and an
/// epoch boundary: the round settles inactivity (nobody voted) and the epoch
/// slides the head vote committee window.
#[test]
fn empty_slots_cross_the_fork_a_round_and_an_epoch() {
    let per_epoch = preset::SLOTS_PER_EPOCH;
    let config = Config::active()
        .with_fork_epoch(ForkName::Gloas, 0)
        .with_fork_epoch(ForkName::Heze, 0)
        .with_fork_epoch(ForkName::Eip8453, 2);
    let mut state = test_state::with_validators_at(ForkName::Heze, 64);

    stf::process_slots(&mut state, 2 * per_epoch, &config).unwrap();
    assert_eq!(state.fork_name(), ForkName::Eip8453);
    assert_eq!(inner(&state).fork.epoch, 2);
    assert!(inner(&state).inactivity_scores.iter().all(|&s| s == 0));
    let window_at_fork = inner(&state).head_vote_committee_window.clone();

    // One round: every active validator missed it.
    stf::process_slots(&mut state, 2 * per_epoch + preset::SLOTS_PER_ROUND, &config).unwrap();
    assert!(
        inner(&state)
            .inactivity_scores
            .iter()
            .all(|&s| s == config.inactivity_score_bias)
    );
    let rounds_in_epoch = per_epoch / preset::SLOTS_PER_ROUND;

    // To the next epoch: the remaining rounds of the epoch, and the epoch.
    stf::process_slots(&mut state, 3 * per_epoch, &config).unwrap();
    assert!(
        inner(&state)
            .inactivity_scores
            .iter()
            .all(|&s| s == rounds_in_epoch * config.inactivity_score_bias)
    );
    let window = &inner(&state).head_vote_committee_window;
    let per_epoch = per_epoch as usize;
    assert_eq!(window[..2 * per_epoch], window_at_fork[per_epoch..]);
    // No height moved: nobody voted.
    assert_eq!(inner(&state).target_checkpoint.height, 1);
    assert!(!state.has_pending_mutations());
}

// ---------------------------------------------------------------------------
// Whole blocks
// ---------------------------------------------------------------------------

/// Two signed blocks with attestations and head votes, through
/// `state_transition` with the state root checked: the first justifies
/// height 1's target and moves to height 2, the second's finality pairs
/// finalize it.
#[test]
fn blocks_with_attestations_and_head_votes_justify_and_finalize() {
    let config = config();
    let state0 = chain_state(32);
    let start = state0.slot();
    let empty = eip8453::HeightCheckpoint::empty();

    // Block 1: every validator's target vote, and a head vote for the
    // previous slot's block with support.
    let mut pre1 = state0.clone();
    stf::process_slots(&mut pre1, start + 1, &config).unwrap();
    let target_1 = inner(&pre1).target_checkpoint;
    let epoch = get_current_epoch(&pre1);
    let mut body = eip8453::BeaconBlockBody::empty();
    body.attestations.push(aggregate(
        &pre1,
        attestation_data(target_1, false, empty),
        epoch,
        |_| true,
    ));
    let voted_root = get_block_root_at_slot(&pre1, start).unwrap();
    let (vote, support) = head_vote(
        &pre1,
        start,
        voted_root,
        constants::PAYLOAD_STATUS_PENDING,
        true,
        &config,
    );
    let committee = get_head_vote_committee(&pre1, start, &config).unwrap();
    body.head_votes.push(vote);
    body.head_vote_support.push(support);
    let block_1 = signed_block(&pre1, body, &config);

    let mut state = state0.clone();
    transition(&mut state, &block_1, &config).unwrap();
    let after_1 = inner(&state);
    assert_eq!(after_1.justified_checkpoint, target_1);
    assert_eq!(after_1.pending_finality.len(), 1);
    assert_eq!(after_1.pending_finality[0].checkpoint, target_1);
    assert_eq!(
        after_1.target_checkpoint,
        eip8453::HeightCheckpoint {
            height: 2,
            root: Root::ZERO
        }
    );
    assert_eq!(after_1.target_slot, start + 1);
    assert!(
        after_1
            .round_participation
            .iter()
            .all(|&flags| flags == 1 << constants::PROGRESS_FLAG_INDEX)
    );
    // Every seat of the voted slot's committee is recorded.
    let seats = &after_1.head_vote_participation
        [preset::SLOTS_PER_EPOCH as usize + (start % preset::SLOTS_PER_EPOCH) as usize];
    assert_eq!(seats.count_ones(), committee.len());

    // Block 2: target votes for height 2 carrying height 1 as the finality
    // pair, and a head vote for block 1.
    let mut pre2 = state.clone();
    stf::process_slots(&mut pre2, start + 2, &config).unwrap();
    let target_2 = inner(&pre2).target_checkpoint;
    // `process_slot` named block 1 as height 2's target.
    assert_eq!(target_2.root, block_1.message_hash_tree_root());
    let mut body = eip8453::BeaconBlockBody::empty();
    body.attestations.push(aggregate(
        &pre2,
        attestation_data(target_2, false, target_1),
        epoch,
        |_| true,
    ));
    let (vote, support) = head_vote(
        &pre2,
        start + 1,
        target_2.root,
        constants::PAYLOAD_STATUS_PENDING,
        true,
        &config,
    );
    body.head_votes.push(vote);
    body.head_vote_support.push(support);
    let block_2 = signed_block(&pre2, body, &config);

    transition(&mut state, &block_2, &config).unwrap();
    let after_2 = inner(&state);
    assert_eq!(after_2.finalized_checkpoint, target_1);
    assert_eq!(after_2.justified_checkpoint, target_2);
    assert_eq!(after_2.pending_finality.len(), 1);
    assert_eq!(after_2.pending_finality[0].checkpoint, target_2);
    assert_eq!(after_2.target_checkpoint.height, 3);
    assert!(
        after_2
            .round_participation
            .iter()
            .all(|&flags| flags == 0b11)
    );

    // A tampered state root is refused by `state_transition`.
    let SignedBeaconBlock::Eip8453(mut tampered) = block_2.clone() else {
        unreachable!()
    };
    tampered.message.state_root = Root::repeat_byte(1);
    let mut replay = state0;
    transition(&mut replay, &block_1, &config).unwrap();
    assert!(transition(&mut replay, &SignedBeaconBlock::Eip8453(tampered), &config).is_err());
}

// ---------------------------------------------------------------------------
// Attestations
// ---------------------------------------------------------------------------

/// `chain_state` advanced one slot, the attestation-processing tests' base.
fn advanced(count: usize) -> (BeaconState, Config) {
    let config = config();
    let mut state = chain_state(count);
    let slot = state.slot() + 1;
    stf::process_slots(&mut state, slot, &config).unwrap();
    (state, config)
}

#[test]
fn process_attestation_credits_progress_once_and_pays_the_proposer() {
    let (mut state, _) = advanced(8);
    let target = inner(&state).target_checkpoint;
    let epoch = get_current_epoch(&state);
    let attestation = aggregate(
        &state,
        attestation_data(target, false, eip8453::HeightCheckpoint::empty()),
        epoch,
        |index| index < 6,
    );
    let proposer = get_beacon_proposer_index(&state).unwrap();
    let before = state.balance(proposer).unwrap();
    let total = get_total_active_balance(&state).unwrap();
    let base = round_base_reward(preset::MAX_EFFECTIVE_BALANCE, total);

    process_attestation(&mut state, &attestation).unwrap();

    let inner_state = inner(&state);
    for index in 0..8 {
        let voted = index < 6;
        assert_eq!(inner_state.progress_participation[index], voted);
        assert_eq!(inner_state.target_participation[index], voted);
        assert_eq!(
            inner_state.round_participation[index],
            if voted {
                1 << constants::PROGRESS_FLAG_INDEX
            } else {
                0
            }
        );
    }
    let divisor = (constants::WEIGHT_DENOMINATOR - constants::PROPOSER_WEIGHT)
        * constants::WEIGHT_DENOMINATOR
        / constants::PROPOSER_WEIGHT;
    let reward = 6 * base * constants::PROGRESS_WEIGHT / divisor;
    assert!(reward > 0);
    assert_eq!(state.balance(proposer).unwrap(), before + reward);

    // The same votes again earn nothing more.
    process_attestation(&mut state, &attestation).unwrap();
    assert_eq!(state.balance(proposer).unwrap(), before + reward);
}

#[test]
fn a_timeout_counts_as_progress_but_not_as_a_target_vote() {
    let (mut state, _) = advanced(4);
    let target = inner(&state).target_checkpoint;
    let epoch = get_current_epoch(&state);
    let attestation = aggregate(
        &state,
        attestation_data(target, true, eip8453::HeightCheckpoint::empty()),
        epoch,
        |_| true,
    );
    process_attestation(&mut state, &attestation).unwrap();
    assert!(inner(&state).progress_participation.iter().all(|&p| p));
    assert!(inner(&state).target_participation.iter().all(|&p| !p));
}

#[test]
fn a_vote_below_the_current_height_credits_only_its_finality_pair() {
    let (mut state, _) = advanced(4);
    let pending_checkpoint = eip8453::HeightCheckpoint {
        height: 1,
        root: Root::repeat_byte(5),
    };
    let inner_state = inner_mut(&mut state);
    inner_state.target_checkpoint = eip8453::HeightCheckpoint {
        height: 3,
        root: Root::repeat_byte(6),
    };
    inner_state.pending_finality = vec![eip8453::PendingFinality {
        checkpoint: pending_checkpoint,
        slot: 1,
        participation: vec![false; 4].into(),
    }]
    .try_into()
    .unwrap();
    let below = eip8453::HeightCheckpoint {
        height: 2,
        root: Root::repeat_byte(7),
    };
    let epoch = get_current_epoch(&state);
    let attestation = aggregate(
        &state,
        attestation_data(below, false, pending_checkpoint),
        epoch,
        |_| true,
    );
    process_attestation(&mut state, &attestation).unwrap();
    let inner_state = inner(&state);
    assert!(
        inner_state.pending_finality[0]
            .participation
            .iter()
            .all(|&p| p)
    );
    assert!(inner_state.progress_participation.iter().all(|&p| !p));
    assert!(
        inner_state
            .round_participation
            .iter()
            .all(|&flags| flags == 1 << constants::FINALITY_FLAG_INDEX)
    );
}

#[test]
fn process_attestation_refuses_what_the_specification_asserts() {
    let (state, _) = advanced(4);
    let target = inner(&state).target_checkpoint;
    let epoch = get_current_epoch(&state);
    let empty = eip8453::HeightCheckpoint::empty();
    let good = aggregate(
        &state,
        attestation_data(target, false, empty),
        epoch,
        |_| true,
    );
    assert!(process_attestation(&mut state.clone(), &good).is_ok());

    // Not the target and no pending finality pair.
    let other = eip8453::HeightCheckpoint {
        height: target.height,
        root: Root::repeat_byte(9),
    };
    let bad_target = aggregate(&state, attestation_data(other, false, empty), epoch, |_| {
        true
    });
    assert!(process_attestation(&mut state.clone(), &bad_target).is_err());

    // A future epoch.
    let mut future = good.clone();
    future.epoch = epoch + 1;
    assert!(process_attestation(&mut state.clone(), &future).is_err());

    // An epoch before the finalized slot's.
    let mut finalized_later = state.clone();
    inner_mut(&mut finalized_later).finalized_slot = state.slot();
    let mut stale = good.clone();
    stale.epoch = epoch - 1;
    assert!(process_attestation(&mut finalized_later, &stale).is_err());

    // Bits of the wrong length.
    let mut short = good.clone();
    short.aggregation_bits = eip8453::AggregationBits::with_length(1);
    assert!(process_attestation(&mut state.clone(), &short).is_err());

    // A bad signature.
    let mut unsigned = good;
    unsigned.signature = BlsSignature(bls::G2_POINT_AT_INFINITY);
    assert!(process_attestation(&mut state.clone(), &unsigned).is_err());
}

// ---------------------------------------------------------------------------
// Head votes
// ---------------------------------------------------------------------------

#[test]
fn process_head_vote_records_same_slot_seats_and_checks_the_payload_status() {
    let (state, config) = advanced(6);
    let previous = state.slot() - 1;
    let root = get_block_root_at_slot(&state, previous).unwrap();
    let committee = get_head_vote_committee(&state, previous, &config).unwrap();

    // A same-slot vote must leave the payload pending.
    let (full, support) = head_vote(
        &state,
        previous,
        root,
        constants::PAYLOAD_STATUS_FULL,
        false,
        &config,
    );
    assert!(process_head_vote(&mut state.clone(), &full, &support, &config).is_err());

    let (vote, support) = head_vote(
        &state,
        previous,
        root,
        constants::PAYLOAD_STATUS_PENDING,
        true,
        &config,
    );
    let mut recorded = state.clone();
    process_head_vote(&mut recorded, &vote, &support, &config).unwrap();
    let index = preset::SLOTS_PER_EPOCH as usize + (previous % preset::SLOTS_PER_EPOCH) as usize;
    let seats = &inner(&recorded).head_vote_participation[index];
    for (position, member) in committee.iter().enumerate() {
        assert_eq!(
            seats.get(position),
            Some(vote.voter_indices.contains(member))
        );
    }

    // A vote for another block of the slot is checked but not recorded, and
    // may name a payload.
    let (other, support) = head_vote(
        &state,
        previous,
        Root::repeat_byte(4),
        constants::PAYLOAD_STATUS_EMPTY,
        false,
        &config,
    );
    let mut unrecorded = state.clone();
    process_head_vote(&mut unrecorded, &other, &support, &config).unwrap();
    assert_eq!(
        inner(&unrecorded).head_vote_participation,
        inner(&state).head_vote_participation
    );

    // No such payload status.
    let (mut bogus, support) = head_vote(
        &state,
        previous,
        Root::repeat_byte(4),
        constants::PAYLOAD_STATUS_EMPTY,
        false,
        &config,
    );
    bogus.data.payload_status = 3;
    assert!(process_head_vote(&mut state.clone(), &bogus, &support, &config).is_err());
}

#[test]
fn process_head_vote_refuses_bad_voters_support_and_timing() {
    let (state, config) = advanced(6);
    let previous = state.slot() - 1;
    let root = get_block_root_at_slot(&state, previous).unwrap();
    let (vote, support) = head_vote(
        &state,
        previous,
        root,
        constants::PAYLOAD_STATUS_PENDING,
        false,
        &config,
    );
    assert!(process_head_vote(&mut state.clone(), &vote, &support, &config).is_ok());

    // Support bits of the wrong length.
    let short = eip8453::HeadVoteSupportBits::with_length(support.len() - 1);
    assert!(process_head_vote(&mut state.clone(), &vote, &short, &config).is_err());

    // Empty, or unsorted, voters.
    let mut empty = vote.clone();
    empty.voter_indices = Default::default();
    let none = eip8453::HeadVoteSupportBits::with_length(0);
    assert!(process_head_vote(&mut state.clone(), &empty, &none, &config).is_err());
    if vote.voter_indices.len() > 1 {
        let mut reversed = vote.clone();
        let mut indices = vote.voter_indices.to_vec();
        indices.reverse();
        reversed.voter_indices = indices.try_into().unwrap();
        assert!(process_head_vote(&mut state.clone(), &reversed, &support, &config).is_err());
    }

    // A tampered signature.
    let mut unsigned = vote.clone();
    unsigned.signature = BlsSignature(bls::G2_POINT_AT_INFINITY);
    assert!(process_head_vote(&mut state.clone(), &unsigned, &support, &config).is_err());

    // Support for a vote older than the previous slot.
    let mut later = state.clone();
    *later.slot_mut() += 1;
    let (_, support_set) = head_vote(
        &state,
        previous,
        root,
        constants::PAYLOAD_STATUS_PENDING,
        true,
        &config,
    );
    assert!(process_head_vote(&mut later.clone(), &vote, &support, &config).is_ok());
    assert!(process_head_vote(&mut later, &vote, &support_set, &config).is_err());

    // No inclusion delay: a vote for the state's own slot.
    let (own, own_support) = head_vote(
        &state,
        state.slot(),
        root,
        constants::PAYLOAD_STATUS_EMPTY,
        false,
        &config,
    );
    assert!(process_head_vote(&mut state.clone(), &own, &own_support, &config).is_err());
}

// ---------------------------------------------------------------------------
// Height events
// ---------------------------------------------------------------------------

#[test]
fn a_progress_quorum_moves_the_height_only_after_the_timeout_delay() {
    let mut state = test_state::with_validators_at(ForkName::Eip8453, 3);
    let target_slot = state.slot();
    inner_mut(&mut state).target_slot = target_slot;
    inner_mut(&mut state).progress_participation = vec![true, true, false].into();
    *state.slot_mut() = target_slot + preset::TIMEOUT_DELAY_SLOTS - 1;
    process_height_events(&mut state).unwrap();
    assert_eq!(inner(&state).target_checkpoint.height, 1);

    *state.slot_mut() = target_slot + preset::TIMEOUT_DELAY_SLOTS;
    process_height_events(&mut state).unwrap();
    let inner_state = inner(&state);
    assert_eq!(inner_state.target_checkpoint.height, 2);
    // A timeout advance justifies nothing.
    assert!(inner_state.pending_finality.is_empty());
    assert_eq!(
        inner_state.justified_checkpoint,
        eip8453::HeightCheckpoint {
            height: 0,
            root: Root::ZERO
        }
    );
}

#[test]
fn finality_takes_the_highest_pending_with_a_quorum_and_drops_those_below() {
    let mut state = test_state::with_validators_at(ForkName::Eip8453, 3);
    let entry = |height: u64, slot: Slot, quorum: bool| eip8453::PendingFinality {
        checkpoint: eip8453::HeightCheckpoint {
            height,
            root: Root::repeat_byte(height as u8),
        },
        slot,
        participation: vec![quorum, quorum, false].into(),
    };
    inner_mut(&mut state).target_checkpoint.height = 6;
    inner_mut(&mut state).pending_finality = vec![
        entry(2, 20, true),
        entry(3, 30, true),
        entry(4, 40, false),
        entry(5, 50, false),
    ]
    .try_into()
    .unwrap();
    process_height_events(&mut state).unwrap();
    let inner_state = inner(&state);
    assert_eq!(inner_state.finalized_checkpoint.height, 3);
    assert_eq!(inner_state.finalized_slot, 30);
    let left: Vec<u64> = inner_state
        .pending_finality
        .iter()
        .map(|pending| pending.checkpoint.height)
        .collect();
    assert_eq!(left, vec![4, 5]);
}

#[test]
fn a_target_quorum_justifies_keeping_only_the_newest_pending_justifications() {
    let mut state = test_state::with_validators_at(ForkName::Eip8453, 3);
    let window = preset::PENDING_FINALITY_WINDOW as u64;
    let entries: Vec<_> = (1..=window)
        .map(|height| eip8453::PendingFinality {
            checkpoint: eip8453::HeightCheckpoint {
                height,
                root: Root::repeat_byte(height as u8),
            },
            slot: height,
            participation: vec![false; 3].into(),
        })
        .collect();
    let target = eip8453::HeightCheckpoint {
        height: window + 1,
        root: Root::repeat_byte(0x40),
    };
    let inner_state = inner_mut(&mut state);
    inner_state.pending_finality = entries.try_into().unwrap();
    inner_state.target_checkpoint = target;
    inner_state.target_slot = 77;
    inner_state.target_participation = vec![true, true, false].into();
    state.latest_block_header_mut().slot = 80;

    process_height_events(&mut state).unwrap();

    let inner_state = inner(&state);
    assert_eq!(inner_state.justified_checkpoint, target);
    let heights: Vec<u64> = inner_state
        .pending_finality
        .iter()
        .map(|pending| pending.checkpoint.height)
        .collect();
    assert_eq!(heights, (2..=window + 1).collect::<Vec<_>>());
    let newest = inner_state.pending_finality.last().unwrap();
    assert_eq!(newest.slot, 77);
    assert_eq!(newest.participation.to_vec(), vec![false; 3]);
    // `advance_height`.
    assert_eq!(
        inner_state.target_checkpoint,
        eip8453::HeightCheckpoint {
            height: window + 2,
            root: Root::ZERO
        }
    );
    assert_eq!(inner_state.target_slot, 80);
    assert_eq!(inner_state.target_participation.to_vec(), vec![false; 3]);
    assert_eq!(inner_state.progress_participation.to_vec(), vec![false; 3]);
}

#[test]
fn advance_height_targets_the_latest_block_with_fresh_participation() {
    let mut state = test_state::with_validators_at(ForkName::Eip8453, 2);
    inner_mut(&mut state).progress_participation = vec![true, true].into();
    inner_mut(&mut state).target_participation = vec![true, false].into();
    state.latest_block_header_mut().slot = 12;
    advance_height(&mut state).unwrap();
    let inner_state = inner(&state);
    assert_eq!(inner_state.target_checkpoint.height, 2);
    assert_eq!(inner_state.target_checkpoint.root, Root::ZERO);
    assert_eq!(inner_state.target_slot, 12);
    assert_eq!(inner_state.progress_participation.to_vec(), vec![false; 2]);
    assert_eq!(inner_state.target_participation.to_vec(), vec![false; 2]);
}

// ---------------------------------------------------------------------------
// Attester slashings and operation limits
// ---------------------------------------------------------------------------

fn indexed(
    state: &BeaconState,
    indices: &[ValidatorIndex],
    data: eip8453::AttestationData,
) -> eip8453::IndexedAttestation {
    let epoch = get_current_epoch(state);
    let signatures: Vec<_> = indices
        .iter()
        .map(|index| {
            sign(
                state,
                *index,
                data.hash_tree_root(),
                constants::DOMAIN_FINALITY_ATTESTER,
                epoch,
            )
        })
        .collect();
    eip8453::IndexedAttestation {
        attesting_indices: indices.to_vec().into(),
        data,
        signature: bls::aggregate(&signatures).unwrap(),
        epoch,
    }
}

#[test]
fn process_attester_slashing_slashes_a_double_target_vote() {
    let (mut state, config) = advanced(6);
    let empty = eip8453::HeightCheckpoint::empty();
    let at = |byte: u8| eip8453::HeightCheckpoint {
        height: 4,
        root: Root::repeat_byte(byte),
    };
    let slashing = eip8453::AttesterSlashing {
        attestation_1: indexed(&state, &[1, 2, 3], attestation_data(at(1), false, empty)),
        attestation_2: indexed(&state, &[2, 3, 4], attestation_data(at(2), false, empty)),
    };
    process_attester_slashing(&mut state, &slashing, &config).unwrap();
    for index in 0..6 {
        assert_eq!(
            state.validator(index).unwrap().slashed,
            index == 2 || index == 3,
            "validator {index}"
        );
    }

    // Two consistent votes are not slashable.
    let consistent = eip8453::AttesterSlashing {
        attestation_1: indexed(&state, &[1], attestation_data(at(1), false, empty)),
        attestation_2: indexed(&state, &[1], attestation_data(at(1), true, empty)),
    };
    assert!(process_attester_slashing(&mut state, &consistent, &config).is_err());
}

#[test]
fn process_legacy_attester_slashing_slashes_a_casper_double_vote() {
    use crate::beacon::containers::shared::{AttestationData, Checkpoint};
    let (mut state, config) = advanced(4);
    let legacy = |byte: u8| AttestationData {
        slot: 1,
        target: Checkpoint {
            epoch: 0,
            root: Root::repeat_byte(byte),
        },
        ..Default::default()
    };
    let indexed_legacy = |data: AttestationData| {
        let domain = get_domain(&state, constants::DOMAIN_BEACON_ATTESTER, Some(0));
        let signing_root = compute_signing_root(data.hash_tree_root(), domain);
        let signatures: Vec<_> = [0usize, 1]
            .iter()
            .map(|index| test_state::sign_for(*index, signing_root))
            .collect();
        gloas::IndexedAttestation {
            attesting_indices: vec![0, 1].into(),
            data,
            signature: bls::aggregate(&signatures).unwrap(),
        }
    };
    let slashing = gloas::AttesterSlashing {
        attestation_1: indexed_legacy(legacy(1)),
        attestation_2: indexed_legacy(legacy(2)),
    };
    process_legacy_attester_slashing(&mut state, &slashing, &config).unwrap();
    assert!(state.validator(0).unwrap().slashed);
    assert!(state.validator(1).unwrap().slashed);
    assert!(!state.validator(2).unwrap().slashed);
}

#[test]
fn process_operations_bounds_the_head_votes_and_pairs_them_with_support() {
    let (state, config) = advanced(4);
    let mut body = eip8453::BeaconBlockBody::empty();
    body.head_vote_support
        .push(eip8453::HeadVoteSupportBits::with_length(0));
    assert!(process_operations(&mut state.clone(), &body, &config).is_err());

    let mut body = eip8453::BeaconBlockBody::empty();
    for _ in 0..=preset::MAX_HEAD_VOTES {
        body.head_votes.push(Default::default());
        body.head_vote_support
            .push(eip8453::HeadVoteSupportBits::with_length(0));
    }
    assert!(process_operations(&mut state.clone(), &body, &config).is_err());

    assert!(
        process_operations(
            &mut state.clone(),
            &eip8453::BeaconBlockBody::empty(),
            &config
        )
        .is_ok()
    );
}
