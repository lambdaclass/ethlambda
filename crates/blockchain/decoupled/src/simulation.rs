//! An in-process lean-style network of nodes on the public time grid.
//!
//! Every validator runs one node, sits in every slot's head vote committee
//! with one seat, weighs one in the finality gadget, proposes slot `s` when it
//! is `s mod n`, and attests once per round in its own slot of the round. An
//! object sent at tick `t` reaches every node at `t` (after that tick's
//! duties), or later when a node is cut off or a Byzantine sender splits its
//! audience: synchrony with delay below `Δ`.
//!
//! The checks are the protocol's observable claims, read at the honest nodes:
//! finalized checkpoints never conflict and only extend, the confirmed node is
//! at or below the finalized one and on the head's chain, the chain grows, and
//! no honest validator signs a slashable pair.

use std::collections::HashMap;

use ethlambda_types::lean_decoupled::attestation_slot;
use ethlambda_types::primitives::H256;

use crate::chain_state::{ChainState, ChainStates, select_attestations};
use crate::duties::head_vote_data;
use crate::params::{Params, slot_of};
use crate::store::{BlockError, Store};
use crate::types::{
    Anchor, AttestationData, BlockInput, BlockRef, Electorate, ForkChoiceNode, HeadVote,
    HeadVoteCommittees, HeadVoteData, HeadVoteMessage, HeightCheckpoint, PayloadStatus, Slot, Tick,
    ValidatorIndex,
};
use crate::validator_client::{FinalitySigningRecord, is_slashable_attestation_data};

/// A block as it travels: one voter per head vote, as on lean.
#[derive(Debug, Clone)]
struct SimBlock {
    root: H256,
    parent_root: H256,
    slot: Slot,
    head_votes: Vec<HeadVoteMessage>,
    support: Vec<bool>,
    attestations: Vec<(ValidatorIndex, AttestationData)>,
}

#[derive(Debug, Clone)]
enum Message {
    /// A block, and whether an honest proposer made it.
    Block(SimBlock, bool),
    Vote(HeadVoteMessage),
    Attestation(ValidatorIndex, AttestationData),
}

/// How a Byzantine validator departs from the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Byzantine {
    /// Two head votes every slot: the head, and its parent's `Empty` node.
    EquivocateVotes,
    /// Two blocks in each of its slots, one to each half of the network,
    /// each relayed to the other half a tick later.
    EquivocateProposals,
    /// Besides its honest attestation, two more each time it attests: a
    /// timeout naming a block that does not exist with a finality pair for
    /// another, and a target vote for a nonexistent block one height up.
    JunkAttestations,
}

struct Node {
    index: ValidatorIndex,
    store: Store,
    states: ChainStates,
    record: FinalitySigningRecord,
    /// Attestations received, with the round they arrived in.
    pool: Vec<(u64, ValidatorIndex, AttestationData)>,
    pending_blocks: Vec<(SimBlock, bool)>,
    online: bool,
    byzantine: Option<Byzantine>,
    finalized_history: Vec<HeightCheckpoint>,
}

/// (sender, recipients or everyone, message)
type Outbox = Vec<(ValidatorIndex, Option<Vec<ValidatorIndex>>, Message)>;

struct Network {
    params: Params,
    electorate: Electorate,
    nodes: Vec<Node>,
    /// Every block ever made, by root, with its parent: the ground truth the
    /// agreement checks walk.
    parents: HashMap<H256, H256>,
    /// What each honest validator signed.
    emitted: HashMap<ValidatorIndex, Vec<AttestationData>>,
    /// Messages a cut-off node missed, delivered when it comes back.
    backlog: HashMap<ValidatorIndex, Vec<Message>>,
    /// Messages to deliver at the next step, by recipient.
    delayed: Vec<(ValidatorIndex, Message)>,
}

const GENESIS: H256 = H256([0x99; 32]);

fn block_root(slot: Slot, proposer: ValidatorIndex) -> H256 {
    let mut bytes = [0xabu8; 32];
    bytes[..8].copy_from_slice(&slot.to_be_bytes());
    bytes[8..16].copy_from_slice(&proposer.to_be_bytes());
    H256(bytes)
}

impl Network {
    fn new(validators: u64, params: Params) -> Self {
        let genesis = BlockRef {
            root: GENESIS,
            slot: 0,
        };
        let state = ChainState::initial(genesis, validators as usize);
        let anchor = Anchor {
            root: GENESIS,
            slot: 0,
            fg: state.checkpoints(),
        };
        let nodes = (0..validators)
            .map(|index| Node {
                index,
                store: Store::new(
                    params,
                    HeadVoteCommittees::EveryValidator {
                        validator_count: validators,
                    },
                    anchor,
                ),
                states: ChainStates::new(genesis, state.clone()),
                record: FinalitySigningRecord::default(),
                pool: Vec::new(),
                pending_blocks: Vec::new(),
                online: true,
                byzantine: None,
                finalized_history: Vec::new(),
            })
            .collect();
        Self {
            params,
            electorate: Electorate::uniform(validators as usize),
            nodes,
            parents: HashMap::new(),
            emitted: HashMap::new(),
            backlog: HashMap::new(),
            delayed: Vec::new(),
        }
    }

    fn honest(&self) -> impl Iterator<Item = &Node> {
        self.nodes.iter().filter(|node| node.byzantine.is_none())
    }

    fn proposer(&self, slot: Slot) -> ValidatorIndex {
        slot % self.nodes.len() as u64
    }

    /// Whether `ancestor` is `root` or one of its ancestors, over every block
    /// ever made.
    fn descends(&self, root: H256, ancestor: H256) -> bool {
        let mut cursor = root;
        loop {
            if cursor == ancestor {
                return true;
            }
            match self.parents.get(&cursor) {
                Some(parent) => cursor = *parent,
                None => return false,
            }
        }
    }

    fn deliver(params: &Params, electorate: &Electorate, node: &mut Node, message: Message) {
        match message {
            Message::Block(block, honest) => {
                node.pending_blocks.push((block, honest));
                Self::drain_pending(params, electorate, node);
            }
            Message::Vote(vote) => {
                let _ = node.store.on_head_vote_message(vote);
            }
            Message::Attestation(validator, data) => {
                let round = node.store.current_round();
                node.pool.push((round, validator, data));
            }
        }
    }

    /// Import a block: derive its chain state, then hand it to the store.
    fn import(
        params: &Params,
        electorate: &Electorate,
        node: &mut Node,
        block: &SimBlock,
    ) -> Result<(), BlockError> {
        if node.store.contains(&block.root) {
            return Err(BlockError::Duplicate);
        }
        if node.states.get(&block.parent_root).is_none() {
            return Err(BlockError::UnknownParent(block.parent_root));
        }
        let at = BlockRef {
            root: block.root,
            slot: block.slot,
        };
        let attestations = block.attestations.iter().map(|(v, data)| (*v, data));
        let fg = node
            .states
            .import(&block.parent_root, at, attestations, params, electorate)
            .expect("blocks carry only valid attestations");
        let input = BlockInput {
            root: block.root,
            parent_root: block.parent_root,
            slot: block.slot,
            parent_payload_status: PayloadStatus::Empty,
            head_votes: block
                .head_votes
                .iter()
                .map(|message| HeadVote {
                    voter_indices: vec![message.validator_index],
                    data: message.data,
                })
                .collect(),
            head_vote_support: block.support.iter().map(|bit| vec![*bit]).collect(),
            fg,
        };
        node.store.on_block(&input)
    }

    fn drain_pending(params: &Params, electorate: &Electorate, node: &mut Node) {
        loop {
            let mut progressed = false;
            for (block, honest) in std::mem::take(&mut node.pending_blocks) {
                match Self::import(params, electorate, node, &block) {
                    Ok(()) | Err(BlockError::Duplicate) => progressed = true,
                    Err(BlockError::UnknownParent(_)) | Err(BlockError::FutureSlot { .. }) => {
                        node.pending_blocks.push((block, honest))
                    }
                    Err(other) if honest => panic!("honest block refused: {other}"),
                    Err(_) => {}
                }
            }
            if !progressed {
                break;
            }
        }
    }

    fn propose(&mut self, i: usize, slot: Slot, outbox: &mut Outbox) {
        let (params, electorate) = (self.params, self.electorate.clone());
        let n = self.nodes.len() as u64;
        let node = &mut self.nodes[i];
        let proposal = node.store.get_ac_proposal();
        assert_ne!(proposal.head.payload_status, PayloadStatus::Pending);
        let parent_state = node
            .states
            .get(&proposal.head.root)
            .expect("the head's state is held");
        let candidates: Vec<(ValidatorIndex, AttestationData)> =
            node.pool.iter().map(|(_, v, data)| (*v, *data)).collect();
        let attestations = select_attestations(parent_state, &candidates)
            .into_iter()
            .map(|index| candidates[index])
            .collect();
        let support = (0..proposal.vote_messages.len())
            .map(|index| proposal.support_indices.contains(&index))
            .collect();
        let block = SimBlock {
            root: block_root(slot, node.index),
            parent_root: proposal.head.root,
            slot,
            head_votes: proposal.vote_messages,
            support,
            attestations,
        };
        self.parents.insert(block.root, block.parent_root);
        Self::import(&params, &electorate, node, &block).expect("own proposal admitted");
        if node.byzantine == Some(Byzantine::EquivocateProposals) {
            // A twin with the same parent and no content.
            let twin = SimBlock {
                root: block_root(slot, node.index + 1000),
                head_votes: Vec::new(),
                support: Vec::new(),
                attestations: Vec::new(),
                ..block.clone()
            };
            self.parents.insert(twin.root, twin.parent_root);
            let index = node.index;
            let (first, second): (Vec<u64>, Vec<u64>) =
                (0..n).filter(|v| *v != index).partition(|v| v % 2 == 0);
            for v in &first {
                self.delayed.push((*v, Message::Block(twin.clone(), false)));
            }
            for v in &second {
                self.delayed
                    .push((*v, Message::Block(block.clone(), false)));
            }
            outbox.push((index, Some(first), Message::Block(block, false)));
            outbox.push((index, Some(second), Message::Block(twin, false)));
        } else {
            let honest = node.byzantine.is_none();
            outbox.push((node.index, None, Message::Block(block, honest)));
        }
    }

    fn vote(&mut self, i: usize, slot: Slot, outbox: &mut Outbox) {
        let node = &mut self.nodes[i];
        let head = node.store.get_ac_vote_head();
        let message = HeadVoteMessage {
            validator_index: node.index,
            data: head_vote_data(&node.store, slot, head),
        };
        node.store
            .on_head_vote_message(message)
            .expect("own vote admitted");
        outbox.push((node.index, None, Message::Vote(message)));
        if node.byzantine == Some(Byzantine::EquivocateVotes)
            && let Some(parent) = node
                .store
                .blocks()
                .find_map(|(root, parent, _)| (root == head.root).then_some(parent).flatten())
        {
            let second = HeadVoteMessage {
                validator_index: node.index,
                data: HeadVoteData::new(slot, ForkChoiceNode::empty(parent)),
            };
            outbox.push((node.index, None, Message::Vote(second)));
        }
    }

    fn attest(&mut self, i: usize, outbox: &mut Outbox) {
        let node = &mut self.nodes[i];
        let frame = node.store.get_ac_frame();
        let Some(input) = node.store.finality_attestation_input(&frame) else {
            return;
        };
        let round = node.store.current_round();
        if let Some(data) = node.record.attest(&input) {
            node.pool.push((round, node.index, data));
            if node.byzantine.is_none() {
                self.emitted.entry(node.index).or_default().push(data);
            }
            outbox.push((node.index, None, Message::Attestation(node.index, data)));
        }
        if node.byzantine == Some(Byzantine::JunkAttestations) {
            let bogus = H256([0xee; 32]);
            let junk = [
                AttestationData {
                    target: HeightCheckpoint::new(input.target.height, bogus),
                    timeout: true,
                    finality: HeightCheckpoint::new(input.target.height.saturating_sub(1), bogus),
                },
                AttestationData {
                    target: HeightCheckpoint::new(input.target.height + 1, bogus),
                    timeout: false,
                    finality: HeightCheckpoint::empty(),
                },
            ];
            for data in junk {
                outbox.push((node.index, None, Message::Attestation(node.index, data)));
            }
        }
    }

    fn step(&mut self, t: Tick) {
        let mut outbox: Outbox = Vec::new();
        let (params, electorate) = (self.params, self.electorate.clone());
        let proposer = self.proposer(slot_of(t));
        for i in 0..self.nodes.len() {
            let node = &mut self.nodes[i];
            let events = node.store.advance_to(t);
            Self::drain_pending(&params, &electorate, node);
            let round = node.store.current_round();
            node.pool.retain(|(arrived, _, _)| arrived + 2 >= round);
            let online = node.online;
            let index = node.index;
            for event in events {
                if !online || event.tick != t {
                    continue;
                }
                if event.propose && proposer == index {
                    self.propose(i, event.slot, &mut outbox);
                }
                if event.head_vote {
                    self.vote(i, event.slot, &mut outbox);
                }
                let round = params.round_of(event.slot);
                if event.support_cutoff
                    && attestation_slot(round, index, params.slots_per_round) == event.slot
                {
                    self.attest(i, &mut outbox);
                }
            }
        }
        for (to, message) in std::mem::take(&mut self.delayed) {
            if let Some(node) = self.nodes.iter_mut().find(|node| node.index == to) {
                Self::deliver(&params, &electorate, node, message);
            }
        }
        for (from, recipients, message) in outbox {
            for node in &mut self.nodes {
                if node.index == from {
                    continue;
                }
                if recipients
                    .as_ref()
                    .is_some_and(|to| !to.contains(&node.index))
                {
                    continue;
                }
                if node.online {
                    Self::deliver(&params, &electorate, node, message.clone());
                } else {
                    self.backlog
                        .entry(node.index)
                        .or_default()
                        .push(message.clone());
                }
            }
        }
        for node in &mut self.nodes {
            node.finalized_history
                .push(node.store.finalized_checkpoint());
            node.states.retain(|root| node.store.contains(root));
            check_confirmed(&node.store);
        }
    }

    fn set_online(&mut self, index: ValidatorIndex, online: bool) {
        let (params, electorate) = (self.params, self.electorate.clone());
        let node = &mut self.nodes[index as usize];
        node.online = online;
        if online {
            for message in self.backlog.remove(&index).unwrap_or_default() {
                Self::deliver(&params, &electorate, node, message);
            }
        }
    }

    fn run(&mut self, ticks: std::ops::Range<Tick>) {
        for t in ticks {
            self.step(t);
        }
    }

    fn finalized_slot(&self, index: usize) -> Slot {
        let node = &self.nodes[index];
        node.store
            .block_slot(&node.store.finalized_checkpoint().root)
            .expect("the finalized block is held")
    }
}

/// `get_confirmed_node` is at or below the finalized node and on the head's
/// chain.
fn check_confirmed(store: &Store) {
    let finalized = ForkChoiceNode::pending(store.finalized_checkpoint().root);
    let confirmed = store.get_confirmed_node();
    assert!(store.is_ancestor(&confirmed, &finalized), "F ⪯ confirmed");
    assert!(
        store.is_compatible(&store.get_head(), &confirmed),
        "confirmed on the head's chain"
    );
}

fn check_agreement(network: &Network) {
    // Honest finalized checkpoints never conflict: every one is on the chain
    // of the deepest.
    let all: Vec<HeightCheckpoint> = network
        .honest()
        .flat_map(|node| node.finalized_history.iter().copied())
        .collect();
    let deepest = all
        .iter()
        .max_by_key(|checkpoint| checkpoint.height)
        .expect("nodes");
    for checkpoint in &all {
        assert!(
            network.descends(deepest.root, checkpoint.root),
            "finalized blocks conflict: {checkpoint:?} / {deepest:?}"
        );
    }
    // Each node's finalized reads only extend.
    for node in network.honest() {
        for pair in node.finalized_history.windows(2) {
            assert!(pair[0].height <= pair[1].height, "finality reverted");
            assert!(network.descends(pair[1].root, pair[0].root));
        }
    }
    // No honest validator signed a slashable pair.
    for emitted in network.emitted.values() {
        for a in emitted {
            for b in emitted {
                assert!(!is_slashable_attestation_data(a, b), "{a:?} / {b:?}");
            }
        }
    }
}

const SLOTS: u64 = 64;

#[test]
fn an_honest_synchronous_network_finalizes_and_confirms() {
    let params = Params::minimal();
    let mut network = Network::new(4, params);
    network.run(0..(4 * SLOTS as Tick));
    check_agreement(&network);

    for (i, node) in network.nodes.iter().enumerate() {
        let finalized = network.finalized_slot(i);
        let confirmed = node.store.get_confirmed_node();
        let confirmed_slot = node.store.block_slot(&confirmed.root).unwrap();
        assert!(
            finalized + 3 * params.slots_per_round >= SLOTS,
            "node {i} finalized slot {finalized} lags the head by more than three rounds"
        );
        assert!(confirmed_slot + 2 >= SLOTS, "confirmed {confirmed:?}");
        assert!(node.store.finalized_checkpoint().height >= 10);
        assert!(!node.store.live_locks().is_empty(), "confirmations lock");
    }
    // Every node ends on the same finalized checkpoint.
    let first = network.nodes[0].store.finalized_checkpoint();
    assert!(
        network
            .nodes
            .iter()
            .all(|n| n.store.finalized_checkpoint() == first)
    );
}

#[test]
fn a_minority_going_offline_keeps_the_chain_live() {
    let params = Params::minimal();
    let mut network = Network::new(4, params);
    network.run(0..80);
    network.set_online(3, false);
    network.run(80..160);
    let before = network.finalized_slot(0);
    network.run(160..240);
    let after = network.finalized_slot(0);
    assert!(after > before, "3 of 4 keep finalizing");
    network.set_online(3, true);
    network.run(240..(4 * SLOTS as Tick));
    check_agreement(&network);
    let tips: Vec<_> = network
        .nodes
        .iter()
        .map(|n| n.store.finalized_checkpoint())
        .collect();
    assert!(
        tips.iter().all(|tip| *tip == tips[0]),
        "the returning node catches up: {tips:?}"
    );
}

#[test]
fn half_offline_stalls_finality_but_not_availability_and_heals() {
    let params = Params::minimal();
    let mut network = Network::new(4, params);
    network.run(0..60);
    network.set_online(2, false);
    network.set_online(3, false);
    network.run(60..140);
    let stalled = network.nodes[0].store.finalized_checkpoint();
    let head_before = network.nodes[0].store.get_head();
    network.run(140..200);
    assert_eq!(
        network.nodes[0].store.finalized_checkpoint(),
        stalled,
        "2 of 4 cannot finalize"
    );
    let head_after = network.nodes[0].store.get_head();
    assert!(
        network.nodes[0].store.block_slot(&head_after.root)
            > network.nodes[0].store.block_slot(&head_before.root),
        "the head keeps growing"
    );
    network.set_online(2, true);
    network.set_online(3, true);
    network.run(200..(8 * SLOTS as Tick));
    check_agreement(&network);
    assert!(
        network.nodes[0].store.finalized_checkpoint().height > stalled.height,
        "finality resumes after healing"
    );
}

/// Prints node 0's view once per slot: `cargo test -p ethlambda-decoupled
/// trace -- --ignored --nocapture`.
#[test]
#[ignore = "diagnostic trace"]
fn trace() {
    let params = Params::minimal();
    let mut network = Network::new(4, params);
    for t in 0..(4 * 40) {
        network.step(t);
        if t % 4 != 3 {
            continue;
        }
        let s = &network.nodes[0].store;
        let slot_of_root = |root: &H256| s.block_slot(root);
        let head = s.get_head();
        let confirmed = s.get_confirmed_node();
        let finalized = s.finalized_checkpoint();
        let justified = s.justified_checkpoint();
        println!(
            "slot {:>3} head {:?} conf {:?} fin {:?} (h {}) J {:?} (h {}) h_max {} contest {} locks {}",
            t / 4,
            slot_of_root(&head.root),
            slot_of_root(&confirmed.root),
            slot_of_root(&finalized.root),
            finalized.height,
            slot_of_root(&justified.root),
            justified.height,
            s.max_height(),
            s.is_fg_contest(),
            s.live_locks().len(),
        );
    }
}

/// One Byzantine validator of four, with `behavior`, over 50 slots.
fn byzantine_run(behavior: Byzantine) -> Network {
    let params = Params::minimal();
    let mut network = Network::new(4, params);
    network.nodes[3].byzantine = Some(behavior);
    network.run(0..200);
    check_agreement(&network);
    network
}

fn assert_honest_progress(network: &Network) {
    for (i, node) in network.nodes.iter().enumerate() {
        if node.byzantine.is_some() {
            continue;
        }
        let finalized = network.finalized_slot(i);
        assert!(
            finalized >= 30,
            "node {i} finalized only up to slot {finalized}"
        );
        let confirmed = node.store.get_confirmed_node();
        assert!(node.store.block_slot(&confirmed.root).unwrap() >= 40);
    }
}

#[test]
fn an_equivocating_voter_cannot_stop_the_honest_majority() {
    let network = byzantine_run(Byzantine::EquivocateVotes);
    assert_honest_progress(&network);
}

#[test]
fn an_equivocating_proposer_cannot_stop_the_honest_majority() {
    let network = byzantine_run(Byzantine::EquivocateProposals);
    assert_honest_progress(&network);
}

#[test]
fn junk_attestations_cannot_stop_the_honest_majority() {
    let network = byzantine_run(Byzantine::JunkAttestations);
    assert_honest_progress(&network);
}
