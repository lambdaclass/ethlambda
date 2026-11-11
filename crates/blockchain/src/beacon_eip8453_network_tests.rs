//! An in-process EIP-8453 network: several beacon chain actors (unspawned
//! [`BlockChainServer`]s driven on a simulated clock) follow one chain from a
//! heze genesis across the EIP-8453 fork, with a test validator client holding
//! every key.
//!
//! Each quarter slot, every node ticks (`BlockChainServer::tick_at`). At a
//! slot's start the proposer builds on its node's `get_ac_proposal` (a heze
//! block before the fork, an EIP-8453 block after it, through
//! `eip8453_block_production`), and every node imports it through the actor's
//! own import path. At the head vote deadline every committee member signs its
//! home node's `get_ac_vote_head`; at the support cutoff every attester of the
//! slot signs its home node's `finality_attestation_input` through its
//! `FinalitySigningRecord`. Votes and attestations reach every node through the
//! p2p layer's gossip rules (`gossip::head_vote`, `gossip::fg_attestation`) and
//! the shared node's `accept_*`, as gossip delivers them.

use std::collections::HashMap;
use std::sync::Arc;

use ethlambda_decoupled::FinalitySigningRecord;
use ethlambda_state_transition::beacon::config::Config;
use ethlambda_state_transition::beacon::constants::{
    BUILDER_INDEX_SELF_BUILD, DOMAIN_BEACON_PROPOSER, DOMAIN_FINALITY_ATTESTER, DOMAIN_HEAD_VOTE,
    DOMAIN_RANDAO,
};
use ethlambda_state_transition::beacon::containers::shared::BeaconBlockHeader;
use ethlambda_state_transition::beacon::containers::{
    BeaconState, SignedBeaconBlock, eip8453, gloas, heze,
};
use ethlambda_state_transition::beacon::eip8453_block_production::{
    assemble_block, pack_attestations,
};
use ethlambda_state_transition::beacon::eip8453_fork_choice::{head_vote_committee, tick_start_ms};
use ethlambda_state_transition::beacon::fork::ForkName;
use ethlambda_state_transition::beacon::fork_choice;
use ethlambda_state_transition::beacon::gossip::{Outcome, fg_attestation, head_vote};
use ethlambda_state_transition::beacon::helpers::accessors::{
    ActiveBalanceCache, CommitteeCache, get_beacon_proposer_index, get_domain, get_randao_mix,
};
use ethlambda_state_transition::beacon::helpers::eip8453::{
    compute_attestation_committee_slot, compute_round_at_slot, get_attestation_committee,
};
use ethlambda_state_transition::beacon::helpers::misc::{
    compute_epoch_at_slot, compute_signing_root,
};
use ethlambda_state_transition::beacon::helpers::test_state;
use ethlambda_state_transition::beacon::preset;
use ethlambda_state_transition::beacon::primitives::{
    BlsSignature, Bytes32, DomainType, Epoch, HashTreeRoot as _, Root, Slot, ValidatorIndex,
};
use ethlambda_state_transition::beacon::stf::{
    self, ExecutionEngine, block::BlockProcessingOptions,
};
use ethlambda_storage::Store;
use ethlambda_storage::backend::InMemoryBackend;

use crate::BlockChainServer;

const GENESIS_TIME: u64 = 1_000_000;
const VALIDATORS: usize = 32;
const NODES: usize = 3;

/// Every fork through heze at genesis, EIP-8453 at `fork_epoch`.
fn config(fork_epoch: Epoch) -> Config {
    let mut config = Config::active();
    for fork in ForkName::ALL {
        if fork != ForkName::Phase0 && fork < ForkName::Eip8453 {
            config = config.with_fork_epoch(fork, 0);
        }
    }
    config = config.with_fork_epoch(ForkName::Eip8453, fork_epoch);
    config.genesis_time = GENESIS_TIME;
    config
}

fn sign(
    state: &BeaconState,
    validator: ValidatorIndex,
    root: Root,
    domain_type: DomainType,
    epoch: Epoch,
) -> BlsSignature {
    let domain = get_domain(state, domain_type, Some(epoch));
    test_state::sign_for(validator as usize, compute_signing_root(root, domain))
}

/// A heze genesis state at slot 0 with `VALIDATORS` keyed validators at the
/// largest effective balance (so every head vote committee draw accepts), its
/// sync committees held by those keys, and the genesis block, whose bid mirrors
/// the state's (as `eth-beacon-genesis` builds it) so no payload is delivered.
///
/// With the fork at epoch 0 the heze genesis is upgraded through
/// `upgrade_to_eip8453`, as a loaded network's `genesis.ssz` is at startup,
/// and the genesis block is an EIP-8453 block.
fn genesis(config: &Config) -> (BeaconState, SignedBeaconBlock) {
    let mut state = test_state::with_signing_validators_at(ForkName::Heze, VALIDATORS);
    *state.slot_mut() = 0;
    *state.genesis_time_mut() = GENESIS_TIME;
    for index in 0..VALIDATORS as u64 {
        state.validator_mut(index).unwrap().effective_balance =
            preset::MAX_EFFECTIVE_BALANCE_ELECTRA;
        *state.balance_mut(index).unwrap() = preset::MAX_EFFECTIVE_BALANCE_ELECTRA;
    }
    let pubkeys: Vec<_> = state.iter_validators().map(|v| v.pubkey).collect();
    let BeaconState::Heze(inner) = &mut state else {
        unreachable!("a heze state")
    };
    for (seat, pubkey) in inner.current_sync_committee.pubkeys.iter_mut().enumerate() {
        *pubkey = pubkeys[seat % pubkeys.len()];
    }
    inner.next_sync_committee = inner.current_sync_committee.clone();
    inner.latest_execution_payload_bid.block_hash = Bytes32::repeat_byte(0xaa);
    if config.eip8453_fork_epoch == 0 {
        let mut state =
            ethlambda_state_transition::beacon::upgrade::upgrade_to_eip8453(&state, config)
                .expect("a heze genesis upgrades");
        let BeaconState::Eip8453(inner) = &mut state else {
            unreachable!("an EIP-8453 state")
        };
        let mut body = eip8453::BeaconBlockBody::empty();
        body.signed_execution_payload_bid.message = inner.latest_execution_payload_bid.clone();
        inner.latest_block_header.body_root = body.hash_tree_root();
        state.apply_pending_mutations();
        let block = SignedBeaconBlock::Eip8453(eip8453::SignedBeaconBlock {
            message: eip8453::BeaconBlock {
                slot: 0,
                proposer_index: 0,
                parent_root: Root::ZERO,
                state_root: state.hash_tree_root(),
                body,
            },
            signature: Default::default(),
        });
        return (state, block);
    }
    let BeaconState::Heze(inner) = &mut state else {
        unreachable!("a heze state")
    };
    let mut body = heze::BeaconBlockBody::empty();
    body.signed_execution_payload_bid.message = inner.latest_execution_payload_bid.clone();
    inner.latest_block_header = BeaconBlockHeader {
        slot: 0,
        proposer_index: 0,
        parent_root: Root::ZERO,
        state_root: Root::ZERO,
        body_root: body.hash_tree_root(),
    };
    state.apply_pending_mutations();
    let block = SignedBeaconBlock::Heze(heze::SignedBeaconBlock {
        message: heze::BeaconBlock {
            slot: 0,
            proposer_index: 0,
            parent_root: Root::ZERO,
            state_root: state.hash_tree_root(),
            body,
        },
        signature: Default::default(),
    });
    (state, block)
}

/// A self-built bid for `slot` on the EMPTY branch of `parent_root` (no
/// payload is ever revealed in this network).
fn self_built_bid(
    state: &BeaconState,
    slot: Slot,
    parent_root: Root,
) -> gloas::SignedExecutionPayloadBid {
    let mut bid = gloas::SignedExecutionPayloadBid::default();
    bid.message.builder_index = BUILDER_INDEX_SELF_BUILD;
    bid.message.slot = slot;
    bid.message.parent_block_hash = *state.latest_block_hash().unwrap();
    bid.message.block_hash = Bytes32::repeat_byte((slot % 200) as u8 + 1);
    bid.message.parent_block_root = parent_root;
    bid.message.prev_randao = get_randao_mix(state, compute_epoch_at_slot(slot));
    bid.message.inclusion_list_bits = Some(heze::InclusionListBits::new());
    bid.signature = BlsSignature(ethlambda_state_transition::beacon::bls::G2_POINT_AT_INFINITY);
    bid
}

/// A signed heze block at `slot` on `parent_root`, whose post-state is
/// `parent_state`.
fn heze_block(
    parent_state: &BeaconState,
    parent_root: Root,
    slot: Slot,
    config: &Config,
) -> SignedBeaconBlock {
    let mut state = parent_state.clone();
    stf::process_slots(&mut state, slot, config).unwrap();
    let epoch = compute_epoch_at_slot(slot);
    let proposer = get_beacon_proposer_index(&state).unwrap();
    let mut body = heze::BeaconBlockBody::empty();
    body.randao_reveal = sign(
        &state,
        proposer,
        epoch.hash_tree_root(),
        DOMAIN_RANDAO,
        epoch,
    );
    body.signed_execution_payload_bid = self_built_bid(&state, slot, parent_root);
    body.sync_aggregate.sync_committee_signature =
        BlsSignature(ethlambda_state_transition::beacon::bls::G2_POINT_AT_INFINITY);
    let mut block = heze::BeaconBlock {
        slot,
        proposer_index: proposer,
        parent_root,
        state_root: Root::ZERO,
        body,
    };
    let unsigned = SignedBeaconBlock::Heze(heze::SignedBeaconBlock {
        message: block.clone(),
        signature: BlsSignature::default(),
    });
    let mut post = state.clone();
    stf::block::process_block(
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
        &state,
        proposer,
        block.hash_tree_root(),
        DOMAIN_BEACON_PROPOSER,
        epoch,
    );
    SignedBeaconBlock::Heze(heze::SignedBeaconBlock {
        message: block,
        signature,
    })
}

/// A signed EIP-8453 block at `slot` on `parent_root` carrying `proposal`'s
/// head votes and the attestations of `pool` that apply.
fn eip8453_block<'a>(
    parent_state: &BeaconState,
    parent_root: Root,
    slot: Slot,
    head_votes: Vec<eip8453::HeadVote>,
    head_vote_support: Vec<eip8453::HeadVoteSupportBits>,
    pool: impl IntoIterator<Item = &'a eip8453::SingleAttestation>,
    config: &Config,
) -> SignedBeaconBlock {
    let mut state = parent_state.clone();
    stf::process_slots(&mut state, slot, config).unwrap();
    let epoch = compute_epoch_at_slot(slot);
    let proposer = get_beacon_proposer_index(&state).unwrap();
    let randao = sign(
        &state,
        proposer,
        epoch.hash_tree_root(),
        DOMAIN_RANDAO,
        epoch,
    );
    let bid = self_built_bid(&state, slot, parent_root);
    let attestations = pack_attestations(&state, pool);
    let (block, _) = assemble_block(
        &state,
        parent_root,
        slot,
        randao,
        bid,
        head_votes,
        head_vote_support,
        attestations,
        config,
    )
    .unwrap();
    let signature = sign(
        &state,
        proposer,
        block.hash_tree_root(),
        DOMAIN_BEACON_PROPOSER,
        epoch,
    );
    SignedBeaconBlock::Eip8453(eip8453::SignedBeaconBlock {
        message: block,
        signature,
    })
}

// ---------------------------------------------------------------------------
// Delivery through the p2p layer's gossip rules
// ---------------------------------------------------------------------------

/// Run a head vote through `head_vote`'s gossip rules on `server`'s node and,
/// on `Accept`, apply it, as the p2p layer does.
fn deliver_head_vote(
    server: &BlockChainServer,
    message: &eip8453::HeadVoteMessage,
    now_ms: u64,
) -> Outcome {
    let node = server.eip8453_node();
    let cheap = node
        .with(|n| head_vote::cheap_checks(n, &server.store, message, now_ms))
        .expect("the fork choice runs");
    if let Err(outcome) = cheap {
        return outcome;
    }
    let is_verified = |root: &Root| {
        node.with(|n| n.engine().is_payload_verified(root))
            .unwrap_or(false)
    };
    match head_vote::stateful_checks(is_verified, &server.store, message) {
        Err(outcome) => outcome,
        Ok(committee) => {
            let applied = node
                .with(|n| n.accept_head_vote(message.clone(), committee, now_ms))
                .expect("the fork choice runs");
            match applied {
                Ok(()) => Outcome::Accept,
                Err(err) => panic!("a validated head vote was refused: {err}"),
            }
        }
    }
}

/// Run a single attestation through `fg_attestation`'s gossip rules on
/// `server`'s node and, on `Accept`, pool it.
fn deliver_attestation(
    server: &BlockChainServer,
    attestation: &eip8453::SingleAttestation,
    subnet: u64,
    now_ms: u64,
) -> Outcome {
    let node = server.eip8453_node();
    let round = node
        .with(|n| fg_attestation::cheap_checks(n, &server.store, attestation, subnet, now_ms))
        .expect("the fork choice runs");
    let round = match round {
        Ok(round) => round,
        Err(outcome) => return outcome,
    };
    let outcome = fg_attestation::stateful_checks(&server.store, attestation);
    if outcome == Outcome::Accept {
        node.with(|n| n.accept_attestation(attestation.clone(), round))
            .expect("the fork choice runs");
    }
    outcome
}

// ---------------------------------------------------------------------------
// The network
// ---------------------------------------------------------------------------

struct Network {
    config: Config,
    nodes: Vec<BlockChainServer>,
    /// Each validator's finality signing record (the validator client's).
    records: HashMap<ValidatorIndex, FinalitySigningRecord>,
    fork_slot: Slot,
    imported: usize,
}

impl Network {
    fn new(fork_epoch: Epoch) -> Self {
        let config = config(fork_epoch);
        let (state, block) = genesis(&config);
        let nodes = (0..NODES)
            .map(|_| {
                let store = fork_choice::get_forkchoice_store(
                    Arc::new(InMemoryBackend::new()),
                    state.clone(),
                    block.clone(),
                    &config,
                )
                .expect("the genesis anchors a store");
                BlockChainServer::for_replay(
                    store,
                    None,
                    ethlambda_state_transition::beacon::constants::SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY,
                )
            })
            .collect();
        Self {
            fork_slot: config.eip8453_fork_epoch * preset::SLOTS_PER_EPOCH,
            config,
            nodes,
            records: HashMap::new(),
            imported: 0,
        }
    }

    fn time(&self, slot: Slot, quarter: u64) -> u64 {
        tick_start_ms(&self.config, (4 * slot + quarter) as i64)
    }

    fn home(&self, validator: ValidatorIndex) -> &BlockChainServer {
        &self.nodes[validator as usize % NODES]
    }

    fn store(&self, node: usize) -> &Store {
        &self.nodes[node].store
    }

    /// The proposer's head state, advanced to `epoch` when older.
    fn duty_state(&self, epoch: Epoch) -> Arc<BeaconState> {
        ethlambda_state_transition::beacon::eip8453_fork_choice::head_state_at_epoch(
            self.store(0),
            epoch,
            &self.config,
        )
        .expect("the proposer's node has a head state")
    }

    async fn tick(&mut self, slot: Slot, quarter: u64) {
        let now = self.time(slot, quarter);
        for node in &mut self.nodes {
            node.tick_at(now).await;
        }
    }

    /// The slot's block, built on node 0's view, imported by every node.
    async fn propose(&mut self, slot: Slot) {
        let now = self.time(slot, 0);
        let block = if slot < self.fork_slot {
            let parent = self.store(0).head().unwrap();
            let parent_state = self.store(0).get_state(&parent).unwrap().unwrap();
            heze_block(&parent_state, parent, slot, &self.config)
        } else {
            let node = self.nodes[0].eip8453_node();
            let proposal = node
                .with(|n| n.proposal(slot, now))
                .expect("the fork choice runs")
                .expect("node 0 recorded the slot's proposal");
            let parent_state = self
                .store(0)
                .get_state(&proposal.head.root)
                .unwrap()
                .expect("the proposal's head has a state");
            let pool: Vec<eip8453::SingleAttestation> = node
                .with(|n| n.all_pooled_attestations().cloned().collect())
                .unwrap();
            eip8453_block(
                &parent_state,
                proposal.head.root,
                slot,
                proposal.head_votes,
                proposal.head_vote_support,
                &pool,
                &self.config,
            )
        };
        for node in &mut self.nodes {
            let outcome = node.import_block(block.clone()).await;
            assert_eq!(
                outcome,
                Some(crate::ImportOutcome::Imported),
                "slot {slot}'s block imports"
            );
        }
        self.imported += 1;
    }

    /// Every distinct committee member of `slot` votes for its home node's
    /// `get_ac_vote_head`, and every node runs the vote through gossip.
    fn vote(&mut self, slot: Slot) -> usize {
        let now = self.time(slot, 1);
        let epoch = compute_epoch_at_slot(slot);
        let state = self.duty_state(epoch);
        let mut voters = head_vote_committee(&state, slot, &self.config).unwrap();
        voters.sort_unstable();
        voters.dedup();
        let mut accepted = 0;
        for voter in voters {
            let Ok(Ok(data)) = self
                .home(voter)
                .eip8453_node()
                .with(|n| n.vote_head(slot, now))
            else {
                continue;
            };
            let data: eip8453::HeadVoteData = data.into();
            let message = eip8453::HeadVoteMessage {
                validator_index: voter,
                data,
                signature: sign(
                    &state,
                    voter,
                    data.hash_tree_root(),
                    DOMAIN_HEAD_VOTE,
                    epoch,
                ),
            };
            for node in &self.nodes {
                let outcome = deliver_head_vote(node, &message, now);
                assert_eq!(
                    outcome,
                    Outcome::Accept,
                    "slot {slot} voter {voter}: {outcome:?}"
                );
            }
            accepted += 1;
        }
        accepted
    }

    /// Every attester of `slot`'s committees attests from its home node's
    /// frame through its signing record, and every node runs the attestation
    /// through gossip.
    fn attest(&mut self, slot: Slot) -> usize {
        let now = self.time(slot, 2);
        let epoch = compute_epoch_at_slot(slot);
        let state = self.duty_state(epoch);
        let round = compute_round_at_slot(slot);
        let mut attested = 0;
        for committee_index in 0..preset::ATTESTATION_COMMITTEES_PER_ROUND as u64 {
            if compute_attestation_committee_slot(round, committee_index).unwrap() != slot {
                continue;
            }
            let members = get_attestation_committee(&state, epoch, committee_index).unwrap();
            for &attester in members.iter() {
                let input = self
                    .home(attester)
                    .eip8453_node()
                    .with(|n| n.finality_attestation_input(slot, now))
                    .unwrap();
                let Ok(Some(input)) = input else {
                    continue;
                };
                let record = self.records.entry(attester).or_default();
                let Some(data) = record.attest(&input) else {
                    continue;
                };
                let data: eip8453::AttestationData = data.into();
                let attestation = eip8453::SingleAttestation {
                    committee_index,
                    attester_index: attester,
                    data,
                    signature: sign(
                        &state,
                        attester,
                        data.hash_tree_root(),
                        DOMAIN_FINALITY_ATTESTER,
                        epoch,
                    ),
                    epoch,
                };
                let subnet =
                    fg_attestation::compute_subnet_for_attestation(&self.config, committee_index);
                for node in &self.nodes {
                    let outcome = deliver_attestation(node, &attestation, subnet, now);
                    assert_eq!(
                        outcome,
                        Outcome::Accept,
                        "slot {slot} attester {attester}: {outcome:?}"
                    );
                }
                attested += 1;
            }
        }
        attested
    }

    async fn run_slot(&mut self, slot: Slot) -> (usize, usize) {
        self.tick(slot, 0).await;
        self.propose(slot).await;
        self.tick(slot, 1).await;
        let votes = if slot >= self.fork_slot {
            self.vote(slot)
        } else {
            0
        };
        self.tick(slot, 2).await;
        let attestations = if slot >= self.fork_slot {
            self.attest(slot)
        } else {
            0
        };
        self.tick(slot, 3).await;
        (votes, attestations)
    }
}

/// Three nodes follow a chain from a heze genesis across the EIP-8453 fork:
/// the handover keeps the pre-fork chain, every head vote and attestation
/// passes gossip validation on every node, and the finality gadget justifies
/// and finalizes heights on every node alike, finalizing EIP-8453 blocks.
#[tokio::test]
async fn an_in_process_network_crosses_the_fork_and_finalizes_with_the_gadget() {
    let mut network = Network::new(1);
    let fork_slot = network.fork_slot;
    let end = fork_slot + 6 * preset::SLOTS_PER_ROUND;
    let mut total_votes = 0;
    let mut total_attestations = 0;
    for slot in 1..=end {
        let (votes, attestations) = network.run_slot(slot).await;
        total_votes += votes;
        total_attestations += attestations;
        if slot == fork_slot {
            // The handover kept the pre-fork chain: the fork's first block
            // builds on the last heze block.
            for node in &network.nodes {
                assert!(
                    node.eip8453_node().is_active(),
                    "the engine runs at the fork"
                );
                let head = node.store.head().unwrap();
                let (head_slot, parent) = node.store.block_entry(&head).unwrap();
                let (parent_slot, _) = node.store.block_entry(&parent).unwrap();
                assert_eq!(
                    (head_slot, parent_slot),
                    (fork_slot, fork_slot - 1),
                    "the fork's first block is the head, on the last heze block"
                );
            }
        }
    }

    assert_eq!(
        network.imported, end as usize,
        "every slot's block imported"
    );
    assert!(total_votes > 0 && total_attestations > 0);

    let head = network.store(0).head().unwrap();
    let finalized = network
        .store(0)
        .fg_finalized_checkpoint()
        .expect("the gadget recorded");
    let justified = network
        .store(0)
        .fg_justified_checkpoint()
        .expect("the gadget recorded");
    for node in 1..NODES {
        assert_eq!(
            network.store(node).head().unwrap(),
            head,
            "node {node}'s head"
        );
        assert_eq!(
            network.store(node).fg_finalized_checkpoint(),
            Some(finalized),
            "node {node}'s finalized checkpoint"
        );
    }
    let (head_slot, _) = network.store(0).block_entry(&head).unwrap();
    assert!(
        head_slot + 1 >= end,
        "the head follows the chain: {head_slot} at {end}"
    );
    assert!(
        finalized.height >= 2,
        "the gadget finalized past its first height: {finalized:?}, justified {justified:?}"
    );
    let (finalized_slot, _) = network.store(0).block_entry(&finalized.root).unwrap();
    assert!(
        finalized_slot >= fork_slot,
        "an EIP-8453 block is finalized"
    );
    // The slot-denominated row pruning reads moved to the gadget's block.
    let stored = network.store(0).latest_finalized().unwrap();
    assert_eq!((stored.root, stored.slot), (finalized.root, finalized_slot));

    // Restart the last node on its own directory: a fresh actor anchors its
    // engine at the stored finalized block and replays the blocks above it,
    // starting from the same finality gadget checkpoints.
    let restarted_store = network.nodes[NODES - 1].store.clone();
    let mut restarted = BlockChainServer::for_replay(
        restarted_store,
        None,
        ethlambda_state_transition::beacon::constants::SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY,
    );
    assert!(!restarted.eip8453_node().is_active());
    restarted.tick_at(network.time(end, 3)).await;
    let (replayed_justified, replayed_finalized) = restarted
        .eip8453_node()
        .with(|n| n.checkpoints())
        .expect("the restart installs the engine");
    assert_eq!(replayed_finalized, finalized.into());
    assert_eq!(replayed_justified, justified.into());
    let replayed_blocks = restarted
        .eip8453_node()
        .with(|n| n.engine().blocks().count())
        .unwrap();
    let live_blocks = network.nodes[0]
        .eip8453_node()
        .with(|n| {
            let engine = n.engine();
            let finalized = engine.finalized_checkpoint().root;
            engine
                .blocks()
                .filter(|(root, _, _)| engine.is_ancestor_root(root, &finalized))
                .count()
        })
        .unwrap();
    assert_eq!(
        replayed_blocks, live_blocks,
        "the replay holds the finalized subtree"
    );
    network.nodes[NODES - 1] = restarted;

    // The network goes on with the restarted node, which catches up from the
    // votes and blocks that follow, and finalizes further alike.
    let more = end + 2 * preset::SLOTS_PER_ROUND;
    for slot in end + 1..=more {
        network.run_slot(slot).await;
    }
    let head = network.store(0).head().unwrap();
    let later = network.store(0).fg_finalized_checkpoint().unwrap();
    assert!(
        later.height > finalized.height,
        "finality moved on: {later:?}"
    );
    for node in 1..NODES {
        assert_eq!(
            network.store(node).head().unwrap(),
            head,
            "node {node}'s head"
        );
        assert_eq!(network.store(node).fg_finalized_checkpoint(), Some(later));
    }
}

/// Why the handover seeds a lock: at the fork's first slot no head vote of the
/// previous slot exists, so without one the available chain's walk stops at
/// its anchor (Casper FFG's finalized block, here genesis) and the fork's
/// first proposal would orphan every block since. With the lock it builds on
/// the last heze block.
#[tokio::test]
async fn the_handover_lock_keeps_the_pre_fork_chain() {
    let mut network = Network::new(1);
    let fork_slot = network.fork_slot;
    for slot in 1..fork_slot {
        network.run_slot(slot).await;
    }
    let last_heze = network.store(0).head().unwrap();
    let genesis = network.store(0).latest_finalized().unwrap().root;
    let now = network.time(fork_slot, 0);

    let unlocked = crate::beacon_eip8453::rebuild_node(network.store(0), now, |_| None)
        .expect("the store anchors an engine");
    let mut unlocked = unlocked;
    let proposal = unlocked.proposal(fork_slot, now).unwrap();
    assert_eq!(
        proposal.head.root, genesis,
        "without a lock the walk stops at its anchor"
    );

    network.tick(fork_slot, 0).await;
    let proposal = network.nodes[0]
        .eip8453_node()
        .with(|n| n.proposal(fork_slot, now))
        .unwrap()
        .unwrap();
    assert_eq!(
        proposal.head.root, last_heze,
        "the seeded lock keeps the chain"
    );
}

/// A network whose EIP-8453 epoch is 0: its genesis is the heze genesis
/// upgraded through the fork, the engine anchors at the genesis block (the
/// first target, whose root `process_slot` fills), and the gadget finalizes
/// from the first round on.
#[tokio::test]
async fn a_network_upgraded_at_genesis_finalizes_with_the_gadget() {
    let mut network = Network::new(0);
    let end = 5 * preset::SLOTS_PER_ROUND;
    for slot in 1..=end {
        network.run_slot(slot).await;
    }
    assert_eq!(
        network.imported, end as usize,
        "every slot's block imported"
    );
    let finalized = network
        .store(0)
        .fg_finalized_checkpoint()
        .expect("the gadget recorded");
    assert!(finalized.height >= 2, "the gadget finalized: {finalized:?}");
    let head = network.store(0).head().unwrap();
    for node in 1..NODES {
        assert_eq!(
            network.store(node).head().unwrap(),
            head,
            "node {node}'s head"
        );
        assert_eq!(
            network.store(node).fg_finalized_checkpoint(),
            Some(finalized)
        );
    }
}
