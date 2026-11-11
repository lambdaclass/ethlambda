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
//!
//! A network built [`Network::with_payloads`] also reveals payloads: past the
//! fork each proposer builds on its proposal's payload branch (FULL when the
//! fork choice extends the parent's payload) with a self-built payload, and its
//! envelope reaches every node through the actor's envelope path
//! (`receive_envelope`, `settle_envelopes`), judged by a stand-in execution
//! client ([`crate::mock_engine`]) that answers `VALID` unless told otherwise
//! for a payload hash.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use ethlambda_decoupled::FinalitySigningRecord;
use ethlambda_engine::EngineClient;
use ethlambda_state_transition::beacon::block_production::empty_sync_aggregate;
use ethlambda_state_transition::beacon::config::Config;
use ethlambda_state_transition::beacon::constants::{
    BUILDER_INDEX_SELF_BUILD, DOMAIN_BEACON_BUILDER, DOMAIN_BEACON_PROPOSER,
    DOMAIN_FINALITY_ATTESTER, DOMAIN_HEAD_VOTE, DOMAIN_RANDAO,
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
use ethlambda_state_transition::beacon::gloas_block_production::{
    Eip8453BlockInputs, assemble_eip8453_block, gloas_payload_inputs, test_support::payload_for,
};
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
use ethlambda_types::decoupled::{ForkChoiceNode, PayloadStatus as NodeStatus};

use crate::BlockChainServer;
use crate::mock_engine::{MockState, mock_engine, status_json};

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

/// The execution block hash of the payload revealed at `slot`.
fn payload_hash(slot: Slot) -> Root {
    let mut bytes = [0x5a; 32];
    bytes[24..].copy_from_slice(&slot.to_be_bytes());
    Root::from(bytes)
}

/// A signed EIP-8453 block at `slot` on `parent_root` (whose post-state is
/// `parent_state`), on the parent's FULL branch when `on_full`, and the
/// signed envelope revealing its self-built payload (block hash
/// [`payload_hash`]), as the Beacon API's production assembles them
/// (`assemble_eip8453_block`).
#[allow(clippy::too_many_arguments)]
fn eip8453_block_with_payload<'a>(
    parent_state: &BeaconState,
    parent_root: Root,
    on_full: bool,
    slot: Slot,
    head_votes: Vec<eip8453::HeadVote>,
    head_vote_support: Vec<eip8453::HeadVoteSupportBits>,
    pool: impl IntoIterator<Item = &'a eip8453::SingleAttestation>,
    config: &Config,
) -> (SignedBeaconBlock, gloas::SignedExecutionPayloadEnvelope) {
    let mut state = parent_state.clone();
    stf::process_slots(&mut state, slot, config).unwrap();
    let epoch = compute_epoch_at_slot(slot);
    let proposer = get_beacon_proposer_index(&state).unwrap();
    let randao_reveal = sign(
        &state,
        proposer,
        epoch.hash_tree_root(),
        DOMAIN_RANDAO,
        epoch,
    );
    let requests = gloas::ExecutionRequests::default();
    let mut inputs = gloas_payload_inputs(&state, on_full, &requests, config).unwrap();
    if !on_full {
        // The payload the EMPTY branch builds on is the last one applied.
        inputs.head_block_hash = *state.latest_block_hash().unwrap();
    }
    let mut execution_payload = payload_for(&inputs);
    execution_payload.block_hash = payload_hash(slot);
    let attestations = pack_attestations(&state, pool);
    let produced = assemble_eip8453_block(
        &state,
        Eip8453BlockInputs {
            randao_reveal,
            graffiti: Bytes32::ZERO,
            head_votes,
            head_vote_support,
            attestations,
            payload_attestations: Vec::new(),
            parent_execution_requests: requests,
            execution_payload,
            blob_kzg_commitments: Vec::new(),
            execution_requests: gloas::ExecutionRequests::default(),
            sync_aggregate: empty_sync_aggregate(),
            inclusion_list_bits: heze::InclusionListBits::new(),
        },
        config,
        BlockProcessingOptions::default(),
    )
    .unwrap();
    assert_eq!(produced.block.parent_root, parent_root);
    let signature = sign(
        &state,
        proposer,
        produced.block.hash_tree_root(),
        DOMAIN_BEACON_PROPOSER,
        epoch,
    );
    let envelope_signature = sign(
        &state,
        proposer,
        produced.envelope.hash_tree_root(),
        DOMAIN_BEACON_BUILDER,
        epoch,
    );
    (
        SignedBeaconBlock::Eip8453(eip8453::SignedBeaconBlock {
            message: produced.block,
            signature,
        }),
        gloas::SignedExecutionPayloadEnvelope {
            message: produced.envelope,
            signature: envelope_signature,
        },
    )
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
        node.with(|n| n.payload_envelope_seen(root))
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
    /// Each node's database, for a restart that reopens it.
    backends: Vec<Arc<InMemoryBackend>>,
    /// The stand-in execution client every node asks, when payloads are
    /// revealed.
    engine: Option<(EngineClient, Arc<Mutex<MockState>>)>,
    /// Each validator's finality signing record (the validator client's).
    records: HashMap<ValidatorIndex, FinalitySigningRecord>,
    fork_slot: Slot,
    imported: usize,
    /// Slots whose proposer stays silent.
    skipped: HashSet<Slot>,
    /// Each proposed block's root, by slot.
    blocks: BTreeMap<Slot, Root>,
    /// EIP-8453 blocks built on their parent's FULL branch.
    full_builds: usize,
    /// Head votes naming a FULL node.
    full_votes: usize,
    /// Invalidated payloads (their blocks' roots): every proposal, head vote,
    /// FG source and head a node computes must stay off them.
    invalidated: Vec<Root>,
    /// `(block slot, at)`: the payload of the block of `block slot` is to be
    /// invalidated on every node by the end of slot `at`'s proposal.
    expected_invalidations: Vec<(Slot, Slot)>,
}

impl Network {
    fn new(fork_epoch: Epoch) -> Self {
        Self::build(fork_epoch, None)
    }

    /// A network whose proposers reveal their payloads past the fork, judged
    /// by one stand-in execution client answering `VALID`.
    async fn with_payloads(fork_epoch: Epoch) -> Self {
        let valid = status_json("VALID", None);
        let engine = mock_engine(valid.clone(), valid).await;
        Self::build(fork_epoch, Some(engine))
    }

    fn build(fork_epoch: Epoch, engine: Option<(EngineClient, Arc<Mutex<MockState>>)>) -> Self {
        let config = config(fork_epoch);
        let (state, block) = genesis(&config);
        let backends: Vec<Arc<InMemoryBackend>> = (0..NODES)
            .map(|_| Arc::new(InMemoryBackend::new()))
            .collect();
        let nodes = backends
            .iter()
            .map(|backend| {
                let store = fork_choice::get_forkchoice_store(
                    backend.clone(),
                    state.clone(),
                    block.clone(),
                    &config,
                )
                .expect("the genesis anchors a store");
                BlockChainServer::for_replay(
                    store,
                    engine.as_ref().map(|(client, _)| client.clone()),
                    ethlambda_state_transition::beacon::constants::SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY,
                )
            })
            .collect();
        Self {
            fork_slot: config.eip8453_fork_epoch * preset::SLOTS_PER_EPOCH,
            config,
            nodes,
            backends,
            engine,
            records: HashMap::new(),
            imported: 0,
            skipped: HashSet::new(),
            blocks: BTreeMap::new(),
            full_builds: 0,
            full_votes: 0,
            invalidated: Vec::new(),
            expected_invalidations: Vec::new(),
        }
    }

    fn reveals_payloads(&self) -> bool {
        self.engine.is_some()
    }

    fn mock(&self) -> &Arc<Mutex<MockState>> {
        &self.engine.as_ref().expect("a network with payloads").1
    }

    /// Restart node `index` on its own database, as a process restart does:
    /// the store reopened from disk (its scratch state rebuilt), the payload
    /// verdicts seeded as `start_actor` seeds them, a fresh actor whose engine
    /// is rebuilt at its first tick.
    fn restart(&mut self, index: usize) {
        let backend: Arc<dyn ethlambda_storage::StorageBackend> = self.backends[index].clone();
        let mut store = Store::from_db_state(backend)
            .expect("same version")
            .expect("a beacon directory");
        store
            .verify_anchor_states()
            .expect("anchor states persisted");
        store.repair_head().expect("the head has a state");
        let engine = self.engine.as_ref().map(|(client, _)| client.clone());
        crate::beacon_payloads::seed_resumed_payload_statuses(&mut store, engine.is_some());
        self.nodes[index] = BlockChainServer::for_replay(
            store,
            engine,
            ethlambda_state_transition::beacon::constants::SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY,
        );
    }

    /// Whether `node` is off every invalidated payload: its block is held by
    /// `server`'s engine, and its chain does not run through an invalidated
    /// payload's FULL node.
    fn is_off_invalidated(&self, server: &BlockChainServer, node: ForkChoiceNode) -> bool {
        server
            .eip8453_node()
            .with(|n| {
                let engine = n.engine();
                engine.contains(&node.root)
                    && self
                        .invalidated
                        .iter()
                        .all(|root| !engine.is_ancestor(&node, &ForkChoiceNode::full(*root)))
            })
            .expect("the fork choice runs")
    }

    /// Every node's head is off every invalidated payload.
    fn assert_heads_off_invalidated(&self, slot: Slot) {
        for (index, server) in self.nodes.iter().enumerate() {
            let Ok(head) = server.eip8453_node().with(|n| n.engine().get_head()) else {
                continue;
            };
            assert!(
                self.is_off_invalidated(server, head),
                "slot {slot}: node {index}'s head {head:?} is on an invalidated payload"
            );
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

    /// The slot's block, built on node 0's view, imported by every node; with
    /// payloads, its envelope then delivered to every node. Nothing for a
    /// skipped slot.
    async fn propose(&mut self, slot: Slot) {
        if self.skipped.contains(&slot) {
            return;
        }
        let now = self.time(slot, 0);
        let mut envelope = None;
        let block = if slot < self.fork_slot {
            let parent = self.store(0).head().unwrap();
            let parent_state = self.store(0).get_state(&parent).unwrap().unwrap();
            heze_block(&parent_state, parent, slot, &self.config)
        } else {
            // Every node's proposal stays off the invalidated payloads.
            for (index, server) in self.nodes.iter().enumerate() {
                let head = server
                    .eip8453_node()
                    .with(|n| n.proposal(slot, now))
                    .expect("the fork choice runs")
                    .expect("the node recorded the slot's proposal")
                    .head;
                assert!(
                    self.is_off_invalidated(server, head),
                    "slot {slot}: node {index}'s proposal {head:?} is on an invalidated payload"
                );
            }
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
            if self.reveals_payloads() {
                let on_full = proposal.head.payload_status == NodeStatus::Full;
                self.full_builds += usize::from(on_full);
                let (block, revealed) = eip8453_block_with_payload(
                    &parent_state,
                    proposal.head.root,
                    on_full,
                    slot,
                    proposal.head_votes,
                    proposal.head_vote_support,
                    &pool,
                    &self.config,
                );
                envelope = Some(revealed);
                block
            } else {
                eip8453_block(
                    &parent_state,
                    proposal.head.root,
                    slot,
                    proposal.head_votes,
                    proposal.head_vote_support,
                    &pool,
                    &self.config,
                )
            }
        };
        for node in &mut self.nodes {
            let outcome = node.import_block(block.clone()).await;
            assert_eq!(
                outcome,
                Some(crate::ImportOutcome::Imported),
                "slot {slot}'s block imports"
            );
        }
        self.blocks.insert(slot, block.message_hash_tree_root());
        self.imported += 1;
        if let Some(envelope) = envelope {
            for node in &mut self.nodes {
                node.receive_envelope(envelope.clone(), now).await;
                node.settle_envelopes().await;
            }
            // A payload the execution client answers `VALID` for is verified
            // on every node, at once.
            let hash = payload_hash(slot);
            let special = {
                let mock = self.mock().lock().unwrap();
                mock.new_payload_by_hash.contains_key(&hash)
                    || mock.forkchoice_by_hash.contains_key(&hash)
            };
            if !special {
                let root = block.message_hash_tree_root();
                for (index, server) in self.nodes.iter().enumerate() {
                    let verified = server
                        .eip8453_node()
                        .with(|n| n.engine().is_payload_verified(&root))
                        .expect("the fork choice runs");
                    assert!(verified, "slot {slot}: node {index} verified the payload");
                }
            }
        }
        let due: Vec<Slot> = self
            .expected_invalidations
            .iter()
            .filter(|(_, at)| *at == slot)
            .map(|(block_slot, _)| *block_slot)
            .collect();
        for block_slot in due {
            let root = self.blocks[&block_slot];
            for (index, server) in self.nodes.iter().enumerate() {
                let invalidated = server
                    .eip8453_node()
                    .with(|n| n.engine().is_payload_invalidated(&root))
                    .expect("the fork choice runs");
                assert!(
                    invalidated,
                    "slot {slot}: node {index} invalidated slot {block_slot}'s payload"
                );
                assert!(!server.store.has_verified_payload(&root));
            }
            self.invalidated.push(root);
        }
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
        // Every node's vote head stays off the invalidated payloads.
        for (index, server) in self.nodes.iter().enumerate() {
            let Ok(Ok(data)) = server.eip8453_node().with(|n| n.vote_head(slot, now)) else {
                continue;
            };
            let node = data.supported_node().expect("a payload status");
            assert!(
                self.is_off_invalidated(server, node),
                "slot {slot}: node {index}'s vote head {node:?} is on an invalidated payload"
            );
        }
        let mut accepted = 0;
        for voter in voters {
            let Ok(Ok(data)) = self
                .home(voter)
                .eip8453_node()
                .with(|n| n.vote_head(slot, now))
            else {
                continue;
            };
            if data.supported_node().map(|node| node.payload_status) == Some(NodeStatus::Full) {
                self.full_votes += 1;
            }
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
        // Every node's FG source stays off the invalidated payloads.
        for (index, server) in self.nodes.iter().enumerate() {
            let Ok(Ok(frame)) = server.eip8453_node().with(|n| n.ac_frame(slot, now)) else {
                continue;
            };
            if let Some(source) = frame.fg_confirmed {
                assert!(
                    self.is_off_invalidated(server, source),
                    "slot {slot}: node {index}'s FG source {source:?} is on an invalidated payload"
                );
            }
        }
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
        self.assert_heads_off_invalidated(slot);
        self.tick(slot, 1).await;
        let votes = if slot >= self.fork_slot {
            self.vote(slot)
        } else {
            0
        };
        self.tick(slot, 2).await;
        self.assert_heads_off_invalidated(slot);
        let attestations = if slot >= self.fork_slot {
            self.attest(slot)
        } else {
            0
        };
        self.tick(slot, 3).await;
        self.assert_heads_off_invalidated(slot);
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

    // Restart the last node on its own directory: a fresh actor over the
    // reopened database anchors its engine at the stored finalized block and
    // replays the blocks above it, starting from the same finality gadget
    // checkpoints.
    network.restart(NODES - 1);
    let now = network.time(end, 3);
    let restarted = &mut network.nodes[NODES - 1];
    assert!(!restarted.eip8453_node().is_active());
    restarted.tick_at(now).await;
    let restarted = &network.nodes[NODES - 1];
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

/// The bid's `parent_block_hash` of the block `root`: which payload it builds
/// on.
fn parent_payload_hash(store: &Store, root: Root) -> Root {
    let block = store.get_signed_block(&root).unwrap().expect("stored");
    crate::beacon_payloads::bid_of(&block)
        .expect("a bid")
        .parent_block_hash
}

/// Past the fork every proposer reveals its payload, which reaches every node
/// through the actor's envelope path and is judged `VALID` by the stand-in
/// execution client: every node verifies it at once, every proposal after the
/// first builds on its parent's FULL branch, the committee of a slot that went
/// empty votes FULL for the last block, the execution client hears FULL heads,
/// and the gadget finalizes EIP-8453 blocks on every node alike.
#[tokio::test]
async fn an_in_process_network_reveals_payloads_builds_on_them_and_finalizes() {
    let mut network = Network::with_payloads(1).await;
    let fork_slot = network.fork_slot;
    let end = fork_slot + 6 * preset::SLOTS_PER_ROUND;
    // Every fifth slot from the fork's fourth goes empty, so its committee
    // votes for the previous block's payload decision.
    network.skipped = (fork_slot + 3..end).step_by(5).collect();
    let mut total_votes = 0;
    for slot in 1..=end {
        let (votes, _) = network.run_slot(slot).await;
        total_votes += votes;
    }

    let skipped = network.skipped.len();
    assert_eq!(network.imported, end as usize - skipped);
    let eip8453_blocks = network.blocks.range(fork_slot..).count();
    assert_eq!(
        network.full_builds + 1,
        eip8453_blocks,
        "every EIP-8453 block but the first (on the last heze block, whose payload \
         was never revealed) builds on its parent's FULL branch"
    );
    assert!(
        network.full_votes > 0 && network.full_votes < total_votes,
        "the empty slots' committees vote FULL: {} of {total_votes}",
        network.full_votes
    );
    // The chain is FULL-built: the last block's bid names its parent's payload.
    let (&last_slot, &last_root) = network.blocks.last_key_value().unwrap();
    let parent = network.store(0).block_entry(&last_root).unwrap().1;
    let parent_slot = network.store(0).block_entry(&parent).unwrap().0;
    assert_eq!(
        parent_payload_hash(network.store(0), last_root),
        payload_hash(parent_slot)
    );

    let finalized = network
        .store(0)
        .fg_finalized_checkpoint()
        .expect("the gadget recorded");
    assert!(finalized.height >= 2, "the gadget finalized: {finalized:?}");
    let (finalized_slot, _) = network.store(0).block_entry(&finalized.root).unwrap();
    assert!(
        finalized_slot >= fork_slot,
        "an EIP-8453 block is finalized"
    );
    let head = network.store(0).head().unwrap();
    assert_eq!(head, last_root, "the head follows the chain");
    for node in 0..NODES {
        assert_eq!(
            network.store(node).head().unwrap(),
            head,
            "node {node}'s head"
        );
        assert_eq!(
            network.store(node).head_payload_status(),
            Some(fork_choice::PayloadStatus::Full),
            "node {node}'s head is the last block's FULL node"
        );
        assert_eq!(
            network.store(node).fg_finalized_checkpoint(),
            Some(finalized)
        );
    }
    // The execution client was told the FULL head.
    let told_head = network.mock().lock().unwrap().requests.iter().any(|body| {
        body.contains("engine_forkchoiceUpdatedV5")
            && body.contains(&format!(
                "\"headBlockHash\":\"{:?}\"",
                payload_hash(last_slot)
            ))
    });
    assert!(told_head, "forkchoiceUpdated named the head's payload");

    // An INVALID verdict about a payload the gadget's justified block builds
    // on (its parent's) is refused on every node: logged, and nothing changes.
    let justified = network.store(0).fg_justified_checkpoint().unwrap();
    let committed = network.store(0).block_entry(&justified.root).unwrap().1;
    let committed_slot = network.store(0).block_entry(&committed).unwrap().0;
    assert_eq!(
        parent_payload_hash(network.store(0), justified.root),
        payload_hash(committed_slot),
        "the justified block builds on its parent's payload"
    );
    for server in &mut network.nodes {
        assert!(!server.condemn_payload_chain(committed, None));
        let (invalidated, holds_justified, head) = server
            .eip8453_node()
            .with(|n| {
                let engine = n.engine();
                (
                    engine.is_payload_invalidated(&committed),
                    engine.contains(&justified.root),
                    engine.get_head(),
                )
            })
            .unwrap();
        assert!(!invalidated && holds_justified);
        assert_eq!(head, ForkChoiceNode::full(last_root));
        // What the engine answered (a refusal changes nothing, so asking
        // again is safe).
        let answer = server
            .eip8453_node()
            .with(|n| n.engine_mut().invalidate_payload(&committed))
            .unwrap();
        assert!(
            matches!(
                answer,
                ethlambda_decoupled::PayloadInvalidation::Committed { .. }
            ),
            "{answer:?}"
        );
        assert_ne!(
            server.store.beacon_block_payload_status(committed),
            fork_choice::PayloadStatusEnum::Invalid
        );
        assert!(server.store.invalid_payloads().is_empty());
        assert!(server.store.block_index().contains_key(&justified.root));
    }
}

/// Two payloads the execution client first accepts optimistically are later
/// found `INVALID`: one through a descendant's `latestValidHash` (the block
/// built on it reveals a payload the client refuses, naming the payload before
/// it as the last valid one), one through `forkchoiceUpdated` naming it as the
/// head. On every node the engine drops each FULL node and the block built on
/// it, every head, proposal, head vote and FG source from then on stays off
/// them (`Network::propose`, `vote`, `attest` and `run_slot` check each), the
/// next block builds on the invalidated block's EMPTY branch, and the gadget
/// keeps finalizing. A node restarted from its database rebuilds an engine
/// that knows the payload invalid and holds nothing built on it.
#[tokio::test]
async fn an_invalidated_payload_is_dropped_on_every_node_and_the_network_moves_off_it() {
    let mut network = Network::with_payloads(1).await;
    let fork_slot = network.fork_slot;
    let walked = fork_slot + 2 * preset::SLOTS_PER_ROUND;
    let direct = walked + 2 * preset::SLOTS_PER_ROUND;
    let end = direct + 3 * preset::SLOTS_PER_ROUND;
    {
        let mut mock = network.mock().lock().unwrap();
        let syncing = status_json("SYNCING", None);
        mock.new_payload_by_hash
            .insert(payload_hash(walked), syncing.clone());
        mock.forkchoice_by_hash
            .insert(payload_hash(walked), syncing.clone());
        mock.new_payload_by_hash.insert(
            payload_hash(walked + 1),
            status_json("INVALID", Some(payload_hash(walked - 1))),
        );
        mock.new_payload_by_hash
            .insert(payload_hash(direct), syncing);
        mock.forkchoice_by_hash.insert(
            payload_hash(direct),
            status_json("INVALID", Some(payload_hash(direct - 1))),
        );
    }
    network.expected_invalidations = vec![(walked, walked + 1), (direct, direct)];

    for slot in 1..=walked + 2 {
        network.run_slot(slot).await;
    }
    let walked_root = network.blocks[&walked];
    let built_on_it = network.blocks[&(walked + 1)];
    for (index, server) in network.nodes.iter().enumerate() {
        let (held, removed) = server
            .eip8453_node()
            .with(|n| {
                (
                    n.engine().contains(&built_on_it),
                    n.engine().is_block_invalidated(&built_on_it),
                )
            })
            .unwrap();
        assert!(
            !held && removed,
            "node {index} dropped the block built on it"
        );
        assert!(!server.store.block_index().contains_key(&built_on_it));
        assert_eq!(
            server.store.beacon_block_payload_status(walked_root),
            fork_choice::PayloadStatusEnum::Invalid
        );
        assert!(
            server
                .store
                .invalid_payloads()
                .contains(&(walked, walked_root))
        );
    }
    // The network moved off it: the next block builds on its EMPTY branch.
    let next = network.blocks[&(walked + 2)];
    assert_eq!(network.store(0).block_entry(&next).unwrap().1, walked_root);
    assert_eq!(
        parent_payload_hash(network.store(0), next),
        payload_hash(walked - 1)
    );

    // Restart a node on its database: its rebuilt engine knows the payload
    // invalid and holds nothing built on it, and its head is off it.
    let restarted = NODES - 1;
    network.restart(restarted);
    let now = network.time(walked + 2, 3);
    network.nodes[restarted].tick_at(now).await;
    let server = &network.nodes[restarted];
    let (invalid, held, head) = server
        .eip8453_node()
        .with(|n| {
            let engine = n.engine();
            (
                engine.is_payload_invalidated(&walked_root),
                engine.contains(&built_on_it),
                engine.get_head(),
            )
        })
        .expect("the restart installs the engine");
    assert!(invalid, "the rebuilt engine replayed the invalidation");
    assert!(
        !held,
        "the rebuilt engine holds nothing built on the payload"
    );
    let finalized_subtree = |server: &BlockChainServer| {
        server
            .eip8453_node()
            .with(|n| {
                let engine = n.engine();
                let finalized = engine.finalized_checkpoint().root;
                let mut roots: Vec<Root> = engine
                    .blocks()
                    .map(|(root, _, _)| root)
                    .filter(|root| engine.is_ancestor_root(root, &finalized))
                    .collect();
                roots.sort();
                roots
            })
            .unwrap()
    };
    assert_eq!(
        finalized_subtree(server),
        finalized_subtree(&network.nodes[0]),
        "the rebuilt engine holds the blocks the live ones do"
    );
    assert!(network.is_off_invalidated(server, head));
    assert!(!server.store.has_verified_payload(&walked_root));
    assert_eq!(
        server.store.beacon_block_payload_status(walked_root),
        fork_choice::PayloadStatusEnum::Invalid,
        "the verdict is seeded again"
    );
    let finalized_then = network.store(0).fg_finalized_checkpoint().unwrap();

    for slot in walked + 3..=end {
        network.run_slot(slot).await;
    }
    // The direct verdict: forkchoiceUpdated found the head's payload invalid,
    // and the next block builds on its EMPTY branch.
    let direct_root = network.blocks[&direct];
    let next = network.blocks[&(direct + 1)];
    assert_eq!(network.store(0).block_entry(&next).unwrap().1, direct_root);
    assert_eq!(
        parent_payload_hash(network.store(0), next),
        payload_hash(direct - 1)
    );
    for server in &network.nodes {
        assert!(
            server
                .store
                .invalid_payloads()
                .contains(&(direct, direct_root))
        );
    }

    assert_eq!(network.imported, end as usize);
    let head = network.store(0).head().unwrap();
    let finalized = network.store(0).fg_finalized_checkpoint().unwrap();
    assert!(
        finalized.height > finalized_then.height,
        "finality moved on: {finalized_then:?} to {finalized:?}"
    );
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
