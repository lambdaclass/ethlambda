//! An in-process network of nodes on the public time grid.
//!
//! Every object sent at tick `t` reaches every node at `t` (after that tick's
//! duties), or later when a node is cut off or a Byzantine sender splits its
//! audience; that is synchrony with delay below `Δ`. The checks are the
//! bundle's observable claims, read at the honest nodes: the three tips nest,
//! finalized reads agree and only extend, the chains grow, and no honest pair
//! of attestations is slashable.

use std::collections::{HashMap, HashSet};

use ethlambda_types::primitives::H256;

use crate::params::{Params, slot_of};
use crate::store::{BlockError, Store};
use crate::types::{Attestation, BlockInput, BlockRef, Electorate, GoldfishVote, Tick};
use crate::validator_client::{Record, slashable};

#[derive(Debug, Clone)]
enum Message {
    /// A block, and whether an honest proposer made it.
    Block(BlockInput, bool),
    Vote(GoldfishVote),
    Attestation(Attestation),
}

/// How a Byzantine validator departs from the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Byzantine {
    /// Two Goldfish votes every slot: the head and its parent.
    EquivocateVotes,
    /// Two blocks in each of its slots, one to each half of the network,
    /// each relayed to the other half a tick later.
    EquivocateProposals,
    /// Besides its honest attestation, two more each round: an empty safe
    /// value with a timeout and a finality pair naming a block that does not
    /// exist, and a target vote for that block one height up.
    JunkAttestations,
}

struct Node {
    index: u64,
    store: Store,
    record: Record,
    pending_blocks: Vec<BlockInput>,
    online: bool,
    byzantine: Option<Byzantine>,
    finalized_history: Vec<BlockRef>,
}

/// (sender, recipients or everyone, message)
type Outbox = Vec<(u64, Option<Vec<u64>>, Message)>;

struct Network {
    nodes: Vec<Node>,
    emitted: Vec<Attestation>,
    /// Messages a cut-off node missed, delivered when it comes back.
    backlog: HashMap<u64, Vec<Message>>,
    /// Messages to deliver at the next step, by recipient.
    delayed: Vec<(u64, Message)>,
}

fn block_root(slot: u64, proposer: u64) -> H256 {
    let mut bytes = [0xabu8; 32];
    bytes[..8].copy_from_slice(&slot.to_be_bytes());
    bytes[8..16].copy_from_slice(&proposer.to_be_bytes());
    H256(bytes)
}

impl Network {
    fn new(validators: u64, params: Params) -> Self {
        let genesis = H256::ZERO;
        let nodes = (0..validators)
            .map(|index| Node {
                index,
                store: Store::from_genesis(
                    params,
                    Electorate::uniform(validators as usize),
                    genesis,
                ),
                record: Record::default(),
                pending_blocks: Vec::new(),
                online: true,
                byzantine: None,
                finalized_history: Vec::new(),
            })
            .collect();
        Self {
            nodes,
            emitted: Vec::new(),
            backlog: HashMap::new(),
            delayed: Vec::new(),
        }
    }

    fn honest(&self) -> impl Iterator<Item = &Node> {
        self.nodes.iter().filter(|node| node.byzantine.is_none())
    }

    fn proposer(&self, slot: u64) -> u64 {
        slot % self.nodes.len() as u64
    }

    fn deliver(node: &mut Node, message: Message) {
        match message {
            Message::Block(block, honest) => {
                node.pending_blocks.push(block);
                Self::drain_pending(node, honest);
            }
            Message::Vote(vote) => {
                node.store.on_goldfish_vote(vote);
            }
            Message::Attestation(attestation) => {
                node.store.on_sg_vote(attestation);
            }
        }
    }

    fn drain_pending(node: &mut Node, honest: bool) {
        loop {
            let mut progressed = false;
            let pending = std::mem::take(&mut node.pending_blocks);
            for block in pending {
                match node.store.on_block(&block) {
                    Ok(()) | Err(BlockError::Duplicate) => progressed = true,
                    Err(BlockError::UnknownParent(_)) | Err(BlockError::FutureSlot { .. }) => {
                        node.pending_blocks.push(block)
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

    fn step(&mut self, t: Tick) {
        let mut outbox: Outbox = Vec::new();
        let n = self.nodes.len() as u64;
        for i in 0..self.nodes.len() {
            let proposer = self.proposer(slot_of(t));
            let node = &mut self.nodes[i];
            let events = node.store.advance_to(t);
            Self::drain_pending(node, true);
            for event in events {
                if !node.online || event.tick != t {
                    continue;
                }
                if event.propose && proposer == node.index {
                    let proposal = node.store.proposal();
                    let block = BlockInput {
                        root: block_root(proposal.slot, node.index),
                        parent_root: proposal.parent_root,
                        slot: proposal.slot,
                        proposer: node.index,
                        votes: proposal.votes,
                        support_votes: proposal.support_votes,
                        attestations: proposal.attestations,
                    };
                    node.store.on_block(&block).expect("own proposal admitted");
                    if node.byzantine == Some(Byzantine::EquivocateProposals) {
                        // A twin with the same parent and no content.
                        let twin = BlockInput {
                            root: block_root(proposal.slot, node.index + 1000),
                            votes: Vec::new(),
                            support_votes: Vec::new(),
                            attestations: Vec::new(),
                            ..block.clone()
                        };
                        let (first, second): (Vec<u64>, Vec<u64>) = (0..n)
                            .filter(|v| *v != node.index)
                            .partition(|v| v % 2 == 0);
                        for v in &first {
                            self.delayed.push((*v, Message::Block(twin.clone(), false)));
                        }
                        for v in &second {
                            self.delayed
                                .push((*v, Message::Block(block.clone(), false)));
                        }
                        outbox.push((node.index, Some(first), Message::Block(block, false)));
                        outbox.push((node.index, Some(second), Message::Block(twin, false)));
                    } else {
                        let honest = node.byzantine.is_none();
                        outbox.push((node.index, None, Message::Block(block, honest)));
                    }
                }
                if event.vote {
                    let head = node.store.goldfish_vote_head();
                    let vote = GoldfishVote {
                        validator: node.index,
                        slot: event.slot,
                        head,
                    };
                    node.store.on_goldfish_vote(vote);
                    outbox.push((node.index, None, Message::Vote(vote)));
                    if node.byzantine == Some(Byzantine::EquivocateVotes)
                        && let Some(parent) = node.store.node(&head).and_then(|b| b.parent)
                    {
                        let second = GoldfishVote {
                            head: parent,
                            ..vote
                        };
                        outbox.push((node.index, None, Message::Vote(second)));
                    }
                }
                if event.attest.is_some() {
                    let input = node.store.attestation_input();
                    let attestation = node.record.create_attestation(node.index, &input);
                    node.store.on_sg_vote(attestation.clone());
                    if node.byzantine.is_none() {
                        self.emitted.push(attestation.clone());
                    }
                    outbox.push((node.index, None, Message::Attestation(attestation)));
                    if node.byzantine == Some(Byzantine::JunkAttestations) {
                        for data in junk_attestations(&input) {
                            let message = Attestation {
                                validator: node.index,
                                data,
                            };
                            outbox.push((node.index, None, Message::Attestation(message)));
                        }
                    }
                }
            }
        }
        for (to, message) in std::mem::take(&mut self.delayed) {
            if let Some(node) = self.nodes.iter_mut().find(|node| node.index == to) {
                Self::deliver(node, message);
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
                    Self::deliver(node, message.clone());
                } else {
                    self.backlog
                        .entry(node.index)
                        .or_default()
                        .push(message.clone());
                }
            }
        }
        for node in &mut self.nodes {
            node.finalized_history.push(node.store.finalized());
            check_nesting(&node.store);
        }
    }

    fn set_online(&mut self, index: u64, online: bool) {
        let node = &mut self.nodes[index as usize];
        node.online = online;
        if online {
            for message in self.backlog.remove(&index).unwrap_or_default() {
                Self::deliver(node, message);
            }
        }
    }

    fn run(&mut self, ticks: std::ops::Range<Tick>) {
        for t in ticks {
            self.step(t);
        }
    }
}

fn check_nesting(store: &Store) {
    let finalized = store.finalized().root;
    let stable = store.stable().root;
    let confirmed = store.confirmed().root;
    assert!(store.is_ancestor(&finalized, &stable), "F ⪯ stable");
    assert!(store.is_ancestor(&stable, &confirmed), "stable ⪯ confirmed");
}

fn check_agreement(network: &Network) {
    // Honest finalized reads agree: every node's finalized block is on the
    // chain of the deepest one.
    let deepest = network
        .honest()
        .max_by_key(|node| node.store.finalized().slot)
        .expect("nodes");
    for node in network.honest() {
        let f = node.store.finalized().root;
        assert!(
            deepest
                .store
                .is_ancestor(&f, &deepest.store.finalized().root),
            "finalized blocks conflict"
        );
    }
    // Each node's finalized reads only extend.
    for node in network.honest() {
        for pair in node.finalized_history.windows(2) {
            assert!(pair[0].slot <= pair[1].slot, "finality reverted");
            assert!(node.store.is_ancestor(&pair[0].root, &pair[1].root) || pair[0] == pair[1]);
        }
    }
    // No honest attestation pair is slashable.
    for a in &network.emitted {
        for b in &network.emitted {
            assert!(!slashable(a, b), "honest evidence: {a:?} / {b:?}");
        }
    }
}

const SLOTS: u64 = 60;

#[test]
fn an_honest_synchronous_network_finalizes_and_nests() {
    let params = Params::with_round_length(3);
    let mut network = Network::new(4, params);
    network.run(0..(4 * SLOTS as Tick));
    check_agreement(&network);

    for node in &network.nodes {
        let finalized = node.store.finalized();
        let confirmed = node.store.confirmed();
        let stable = node.store.stable();
        assert!(
            finalized.slot + 3 * params.slots_per_round >= SLOTS,
            "node {} finalized slot {} lags the head by more than three rounds",
            node.index,
            finalized.slot
        );
        assert!(confirmed.slot + 2 >= SLOTS, "confirmed {confirmed:?}");
        assert!(
            stable.slot + 2 * params.slots_per_round >= SLOTS,
            "stable {stable:?}"
        );
        assert!(node.store.finalized_height() >= 5);
    }
    // Every node ends on the same finalized block.
    let first = network.nodes[0].store.finalized();
    assert!(network.nodes.iter().all(|n| n.store.finalized() == first));
}

#[test]
fn a_minority_going_offline_keeps_the_chain_live() {
    let params = Params::with_round_length(3);
    let mut network = Network::new(4, params);
    network.run(0..80);
    network.set_online(3, false);
    network.run(80..160);
    let before = network.nodes[0].store.finalized();
    network.run(160..240);
    let after = network.nodes[0].store.finalized();
    assert!(after.slot > before.slot, "3 of 4 keep finalizing");
    network.set_online(3, true);
    network.run(240..(4 * SLOTS as Tick));
    check_agreement(&network);
    let tips: HashSet<_> = network.nodes.iter().map(|n| n.store.finalized()).collect();
    assert_eq!(tips.len(), 1, "the returning node catches up: {tips:?}");
}

#[test]
fn half_offline_stalls_finality_but_not_availability_and_heals() {
    let params = Params::with_round_length(3);
    let mut network = Network::new(4, params);
    network.run(0..60);
    network.set_online(2, false);
    network.set_online(3, false);
    network.run(60..140);
    let stalled = network.nodes[0].store.finalized();
    network.run(140..200);
    assert_eq!(
        network.nodes[0].store.finalized(),
        stalled,
        "2 of 4 cannot finalize"
    );
    network.set_online(2, true);
    network.set_online(3, true);
    network.run(200..(8 * SLOTS as Tick));
    check_agreement(&network);
    assert!(
        network.nodes[0].store.finalized().slot > stalled.slot,
        "finality resumes after healing"
    );
}

fn slot_of_grade(store: &Store, grade: Option<Option<H256>>) -> Option<Option<u64>> {
    grade.map(|g| g.and_then(|root| store.block_slot(&root)))
}

/// Prints node 0's view once per slot: `cargo test -p ethlambda-decoupled
/// trace -- --ignored --nocapture`.
#[test]
#[ignore = "diagnostic trace"]
fn trace() {
    let params = Params::with_round_length(3);
    let mut network = Network::new(4, params);
    for t in 0..(4 * 40) {
        network.step(t);
        if t % 4 != 3 {
            continue;
        }
        let s = &network.nodes[0].store;
        let (j, hj) = s.justified();
        let g = s.saved_grades();
        println!(
            "slot {:>3} head {:>3} conf {:>3} stable {:>3} fin {:>3} (h_F {}) J {:>3} (h_j {}) h_max {} G2 {:?} G1 {:?} G0 {:?}",
            t / 4,
            s.block_slot(&s.head()).unwrap(),
            s.confirmed().slot,
            s.stable().slot,
            s.finalized().slot,
            s.finalized_height(),
            j.slot,
            hj,
            s.max_height(),
            slot_of_grade(s, g.g2),
            slot_of_grade(s, g.g1),
            slot_of_grade(s, g.g0),
        );
    }
    for a in network.emitted.iter().rev().take(4) {
        println!("{a:?}");
    }
}

/// Two attestations nobody honest would send, for this round.
fn junk_attestations(input: &crate::AttestationInput) -> [crate::types::AttestationData; 2] {
    use crate::types::{AttestationData, FinalityVote, HeightVote};
    let bogus = H256([0xee; 32]);
    let height = input.source.map_or(1, |source| source.height);
    [
        AttestationData::new(
            input.round,
            None,
            Some(HeightVote {
                height,
                entry: bogus,
                timeout: true,
            }),
            Some(FinalityVote {
                height: input.justified_height + 1,
                target: bogus,
            }),
        ),
        AttestationData::new(
            input.round,
            Some(bogus),
            Some(HeightVote {
                height: height + 1,
                entry: bogus,
                timeout: false,
            }),
            None,
        ),
    ]
}

/// One Byzantine validator of four, with `behavior`, over 50 slots.
fn byzantine_run(behavior: Byzantine) -> Network {
    let params = Params::with_round_length(3);
    let mut network = Network::new(4, params);
    network.nodes[3].byzantine = Some(behavior);
    network.run(0..200);
    check_agreement(&network);
    network
}

fn assert_honest_progress(network: &Network) {
    for node in network.honest() {
        assert!(
            node.store.finalized().slot >= 30,
            "node {} finalized only up to {:?}",
            node.index,
            node.store.finalized()
        );
        assert!(node.store.confirmed().slot >= 45);
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
