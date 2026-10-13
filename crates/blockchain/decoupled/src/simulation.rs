//! An in-process network of nodes on the public time grid.
//!
//! Every object sent at tick `t` reaches every node at `t` (after that tick's
//! duties), or later when a node is cut off or a Byzantine sender splits its
//! audience; that is synchrony with delay below `Δ`. The checks are the
//! observable claims, read at the honest nodes: the outputs nest
//! (`F ⪯ confirmed ⪯ head`), finalized reads agree and only extend, the chains
//! grow, and no honest pair of attestations is slashable.

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
    /// Besides its honest attestations, two more every slot: a timeout and a
    /// finality pair naming a block that does not exist, and a target vote
    /// for that block one height up.
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
    /// Honest attestations, with the tick they were emitted at.
    emitted: Vec<(Tick, Attestation)>,
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
                node.store.on_attestation(attestation);
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
                        && let Some(parent) = node.store.parent(&head)
                    {
                        let second = GoldfishVote {
                            head: parent,
                            ..vote
                        };
                        outbox.push((node.index, None, Message::Vote(second)));
                    }
                }
                if event.attest {
                    let input = node.store.attestation_input();
                    if let Some(attestation) = node.record.create_attestation(node.index, &input) {
                        node.store.on_attestation(attestation.clone());
                        if node.byzantine.is_none() {
                            self.emitted.push((t, attestation.clone()));
                        }
                        outbox.push((node.index, None, Message::Attestation(attestation)));
                    }
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

    /// Honest attestations emitted in `ticks`.
    fn emitted_in(&self, ticks: std::ops::Range<Tick>) -> usize {
        self.emitted
            .iter()
            .filter(|(t, _)| ticks.contains(t))
            .count()
    }
}

fn check_nesting(store: &Store) {
    let finalized = store.finalized().root;
    let confirmed = store.confirmed().root;
    let head = store.head();
    assert!(store.is_ancestor(&finalized, &confirmed), "F ⪯ confirmed");
    assert!(store.is_ancestor(&confirmed, &head), "confirmed ⪯ head");
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
    for (_, a) in &network.emitted {
        for (_, b) in &network.emitted {
            assert!(!slashable(a, b), "honest evidence: {a:?} / {b:?}");
        }
    }
}

const SLOTS: u64 = 60;

#[test]
fn an_honest_synchronous_network_finalizes_and_nests() {
    let mut network = Network::new(4, Params::default());
    network.run(0..(4 * SLOTS as Tick));
    check_agreement(&network);

    for node in &network.nodes {
        let finalized = node.store.finalized();
        let confirmed = node.store.confirmed();
        assert!(
            finalized.slot + 8 >= SLOTS,
            "node {} finalized slot {} lags the head by more than 8 slots",
            node.index,
            finalized.slot
        );
        // Full participation fast locks every slot's proposal.
        assert!(confirmed.slot + 2 >= SLOTS, "confirmed {confirmed:?}");
        assert!(node.store.fg_confirmed().is_some());
        assert!(node.store.finalized_height() >= 10);
    }
    // Every node ends on the same finalized block.
    let first = network.nodes[0].store.finalized();
    assert!(network.nodes.iter().all(|n| n.store.finalized() == first));
}

#[test]
fn a_minority_going_offline_keeps_the_chain_live() {
    let mut network = Network::new(4, Params::default());
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
    let mut network = Network::new(4, Params::default());
    network.run(0..60);
    network.set_online(2, false);
    network.set_online(3, false);
    network.run(60..140);
    let stalled = network.nodes[0].store.finalized();
    let confirmed_before = network.nodes[0].store.confirmed();
    network.run(140..200);
    assert_eq!(
        network.nodes[0].store.finalized(),
        stalled,
        "2 of 4 cannot finalize"
    );
    // Half of the committee still fast locks: the confirmed chain grows.
    assert!(network.nodes[0].store.confirmed().slot > confirmed_before.slot);
    network.set_online(2, true);
    network.set_online(3, true);
    network.run(200..(8 * SLOTS as Tick));
    check_agreement(&network);
    assert!(
        network.nodes[0].store.finalized().slot > stalled.slot,
        "finality resumes after healing"
    );
}

#[test]
fn attestation_traffic_dies_down_while_finality_stalls() {
    let mut network = Network::new(4, Params::default());
    network.run(0..60);
    network.set_online(2, false);
    network.set_online(3, false);
    // Let the online pair cast what the stalled height asks of them.
    network.run(60..100);
    let quiet_from = network.emitted.len();
    network.run(100..200);
    assert_eq!(
        network.emitted.len(),
        quiet_from,
        "no height progress, no new attestations: {:?}",
        &network.emitted[quiet_from..]
    );
    // Every slot of a synchronous, finalizing run brings something new.
    let mut live = Network::new(4, Params::default());
    live.run(0..200);
    assert!(live.emitted_in(100..200) > 0);
}

#[test]
fn a_lone_validator_slow_locks_without_a_fast_quorum() {
    // One validator of four online: it never sees half of a committee, so
    // nothing fast locks, but each slot confirms a chain on its own vote, and
    // k such slots in a row slow lock their common prefix.
    let params = Params::default();
    let mut network = Network::new(4, params);
    network.run(0..40);
    for index in 1..4 {
        network.set_online(index, false);
    }
    network.run(40..120);
    let store = &network.nodes[0].store;
    assert_eq!(store.fg_confirmed(), None, "1 of 4 is not half a committee");
    let locks = store.locks();
    assert!(!locks.is_empty(), "k consecutive confirmations slow lock");
    let confirmed = store.confirmed();
    assert!(
        confirmed.slot >= 20,
        "the slow lock follows the chain: {confirmed:?}"
    );
}

#[test]
fn locks_expire_when_not_renewed() {
    let params = Params::default();
    let mut network = Network::new(4, params);
    network.run(0..40);
    // Everyone else goes dark and the remaining validator stops voting too:
    // no confirmation renews any lock.
    for index in 0..4 {
        network.set_online(index, false);
    }
    network.run(40..(40 + 4 * (params.lock_period as Tick + 2)));
    let store = &network.nodes[0].store;
    assert!(store.locks().is_empty(), "{:?}", store.locks());
    assert_eq!(store.confirmed(), store.finalized());
}

/// Prints node 0's view once per slot: `cargo test -p ethlambda-decoupled
/// trace -- --ignored --nocapture`.
#[test]
#[ignore = "diagnostic trace"]
fn trace() {
    let mut network = Network::new(4, Params::default());
    for t in 0..(4 * 40) {
        network.step(t);
        if t % 4 != 3 {
            continue;
        }
        let s = &network.nodes[0].store;
        let (j, hj) = s.justified();
        let frame = s.frame();
        println!(
            "slot {:>3} head {:>3} conf {:>3} fgc {:?} fin {:>3} (h_F {}) J {:>3} (h_j {}) h_max {} root {:?} floor {} locks {}",
            t / 4,
            s.block_slot(&s.head()).unwrap(),
            s.confirmed().slot,
            s.fg_confirmed().map(|b| b.slot),
            s.finalized().slot,
            s.finalized_height(),
            j.slot,
            hj,
            s.max_height(),
            s.block_slot(&frame.root),
            frame.floor,
            s.locks().len(),
        );
    }
    for (_, a) in network.emitted.iter().rev().take(4) {
        println!("{a:?}");
    }
}

/// Two attestations nobody honest would send.
fn junk_attestations(input: &crate::AttestationInput) -> [crate::types::AttestationData; 2] {
    use crate::types::{AttestationData, FinalityVote, HeightVote};
    let bogus = H256([0xee; 32]);
    let height = input.source.map_or(1, |source| source.height);
    [
        AttestationData::new(
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
    let mut network = Network::new(4, Params::default());
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
