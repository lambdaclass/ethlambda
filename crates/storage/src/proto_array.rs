//! Cached LMD GHOST weights for the beacon fork choice.
//!
//! A node array over the block tree fork choice weighs (Lighthouse's
//! proto-array layout, one entry per block), whose weights are kept current as
//! votes arrive instead of being re-tallied from every validator's latest
//! message on each head computation. That tally was the one part of the head
//! walk proportional to the validator set; everything else it does is
//! proportional to the unfinalized blocks.
//!
//! # What is cached, and what is not
//!
//! Each block carries the three gloas fork-choice nodes, `PENDING`, `EMPTY` and
//! `FULL`, as two arrays indexed by [`PayloadStatus`]:
//!
//! - `own`: the summed balance of the votes that land on that node itself;
//! - `total`: that node's subtree weight, the value
//!   `fork_choice::compute_node_weights` gives it (before the proposer boost).
//!   `total[EMPTY]` and `total[FULL]` add the `PENDING` totals of the children
//!   that build on that branch; `total[PENDING]` adds both branches.
//!
//! A vote batch updates `own` and marks the array dirty; the next read
//! refreshes every `total` in one reverse pass over the nodes, which is the
//! least work when many batches arrive between two reads. The proposer boost,
//! gloas's previous-slot rule and the walk bound depend on the clock and are
//! applied by the reader, never cached.
//!
//! # Staleness
//!
//! Anything the array cannot follow incrementally marks it stale (finality
//! pruning, a live-window removal, a restart), and so does a read whose
//! balances snapshot, rule set or block index differs from the one the array
//! follows. A stale array ignores votes; the next read rebuilds it from the
//! store's latest messages, which is the tally the head walk used to pay on
//! every call. So incremental updates are an optimization over a rebuild that
//! is always available, and the tests hold the two equal.
//!
//! Each validator's counted vote is remembered by node index (`applied`), not by
//! root: a root removed from the block index can come back (the restart head
//! repair drops rows whose state was never written, and those blocks are
//! imported again), and a root-keyed record would then subtract a vote from a
//! node it was never added to. A removal marks the array stale, so every index
//! it holds stays valid until the rebuild replaces them.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ethlambda_types::{
    beacon::{
        fork_choice::{
            BlockPayloadLink, ForkChoiceNode, JustifiedBalances, LatestMessage, PayloadStatus,
        },
        primitives::{Gwei, Slot, ValidatorIndex},
    },
    primitives::H256,
};
use tracing::warn;

/// The rule set votes are mapped and weight flows under. Mirrors
/// `ethlambda-state-transition`'s `ForkRules`, which this crate cannot name:
/// under pre-gloas rules every block is a single full node whatever its own
/// payload link says, which is how the head walk reads a tree before the gloas
/// fork epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeightRules {
    PreGloas,
    Gloas,
}

/// Why a read rebuilt the array, for the rebuild counter's `reason` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RebuildReason {
    /// Never built in this process: a fresh store or a restart.
    Unbuilt,
    /// Finality pruning dropped rows from the block index.
    Prune,
    /// Rows were removed from the live window (payload invalidation, or the
    /// restart head repair).
    Removal,
    /// The justified checkpoint's balances snapshot changed.
    Balances,
    /// The current slot crossed into (or, in tests, out of) the gloas rules.
    Rules,
    /// The block index holds a root the array has no node for: a block
    /// written without `Store::insert_fork_choice_node`.
    Coverage,
    /// A payload link the array lacked at build time is now recorded, and
    /// votes already counted on that block depend on it.
    Link,
    /// A vote's removal would have taken a weight below zero. Only a bug
    /// reaches it; the rebuild repairs the array, and the warning names it.
    Underflow,
}

impl RebuildReason {
    pub(crate) fn label(self) -> &'static str {
        match self {
            RebuildReason::Unbuilt => "unbuilt",
            RebuildReason::Prune => "prune",
            RebuildReason::Removal => "removal",
            RebuildReason::Balances => "balances",
            RebuildReason::Rules => "rules",
            RebuildReason::Coverage => "coverage",
            RebuildReason::Link => "link",
            RebuildReason::Underflow => "underflow",
        }
    }
}

/// Why a read could not produce the weights: the same two conditions on which
/// `fork_choice::compute_node_weights` fails its head computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoArrayError {
    /// A block at or above the bound needed its payload link (a vote made after
    /// its slot, or weight to hand to its parent) and the store has none.
    MissingLink(H256),
    /// A gloas block at or above the bound, whose parent is too, has weight to
    /// hand to a parent branch its link does not name.
    MissingParentStatus(H256),
}

/// Where one validator's vote is counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Applied {
    node: u32,
    status: PayloadStatus,
    /// Counted on a block whose payload link was unknown while the vote needed
    /// it (made after the block's slot, under the gloas rules). It sits on the
    /// `PENDING` node as a placeholder, and the node's `unresolved_votes`
    /// counts it, so a read that weighs that block fails the way the tally
    /// does instead of answering with a guessed branch.
    unresolved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Node {
    root: H256,
    slot: Slot,
    parent: Option<u32>,
    /// `None` when neither a recorded link nor the block was available when
    /// the node was built; see [`Applied::unresolved`].
    link: Option<BlockPayloadLink>,
    own: [Gwei; 3],
    total: [Gwei; 3],
    unresolved_votes: u32,
}

/// One node as [`ProtoArray::diff_against_rebuild`] compares it: the parent
/// named by root, since two arrays can number the same nodes differently.
#[derive(Debug, PartialEq, Eq)]
struct ComparedNode {
    slot: Slot,
    parent: Option<H256>,
    own: [Gwei; 3],
    total: [Gwei; 3],
    unresolved_votes: u32,
}

/// The cache itself; see the module documentation.
#[derive(Debug, Clone)]
pub(crate) struct ProtoArray {
    /// Every parent before its children.
    nodes: Vec<Node>,
    indices: HashMap<H256, u32, foldhash::fast::RandomState>,
    /// By validator index; `None` for a validator whose vote counts nowhere
    /// (none yet, an equivocator, a zero balance, or a root with no node).
    applied: Vec<Option<Applied>>,
    /// The snapshot every counted vote is weighed by.
    balances: Option<Arc<JustifiedBalances>>,
    rules: WeightRules,
    /// `Some` while the array must be rebuilt before it is read.
    stale: Option<RebuildReason>,
    /// `own` changed since `total` was last refreshed.
    dirty: bool,
}

impl Default for ProtoArray {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            indices: HashMap::default(),
            applied: Vec::new(),
            balances: None,
            rules: WeightRules::PreGloas,
            stale: Some(RebuildReason::Unbuilt),
            dirty: false,
        }
    }
}

const fn slot_of(status: PayloadStatus) -> usize {
    status as usize
}

const PENDING: usize = slot_of(PayloadStatus::Pending);
const EMPTY: usize = slot_of(PayloadStatus::Empty);
const FULL: usize = slot_of(PayloadStatus::Full);

impl ProtoArray {
    /// Marks the array for a rebuild on its next read, keeping the first
    /// reason if it is already stale.
    pub(crate) fn mark_stale(&mut self, reason: RebuildReason) {
        if self.stale.is_none() {
            self.stale = Some(reason);
        }
    }

    /// Why a read with these inputs must rebuild first, if it must.
    pub(crate) fn rebuild_reason(
        &self,
        index: &HashMap<H256, (Slot, H256)>,
        balances: &Arc<JustifiedBalances>,
        rules: WeightRules,
    ) -> Option<RebuildReason> {
        if let Some(reason) = self.stale {
            return Some(reason);
        }
        if !self
            .balances
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, balances))
        {
            return Some(RebuildReason::Balances);
        }
        if self.rules != rules {
            return Some(RebuildReason::Rules);
        }
        if index.keys().any(|root| !self.indices.contains_key(root)) {
            return Some(RebuildReason::Coverage);
        }
        // Votes counted while their block's link was unknown sit on a
        // placeholder; once [`Self::fill_missing_links`] has found the link,
        // only a rebuild puts them on their branch.
        if self
            .nodes
            .iter()
            .any(|node| node.unresolved_votes > 0 && node.link.is_some())
        {
            return Some(RebuildReason::Link);
        }
        None
    }

    /// Replaces the whole array with one built from scratch: a node per
    /// `index` entry and every non-equivocating latest message counted at the
    /// node it lands on. `link` answers a block's recorded payload link.
    pub(crate) fn rebuild(
        &mut self,
        index: &HashMap<H256, (Slot, H256)>,
        link: impl Fn(&H256) -> Option<BlockPayloadLink>,
        latest_messages: &[Option<LatestMessage>],
        equivocating: &HashSet<ValidatorIndex>,
        balances: Arc<JustifiedBalances>,
        rules: WeightRules,
    ) {
        // Ancestors first: a parent's slot is below its child's.
        let mut entries: Vec<(Slot, H256, H256)> = index
            .iter()
            .map(|(&root, &(slot, parent_root))| (slot, root, parent_root))
            .collect();
        entries.sort_unstable();

        self.nodes = Vec::with_capacity(entries.len());
        self.indices = HashMap::with_capacity_and_hasher(entries.len(), Default::default());
        for (slot, root, parent_root) in entries {
            let parent = self.indices.get(&parent_root).copied();
            let node_index = u32::try_from(self.nodes.len()).expect("node count fits u32");
            self.nodes.push(Node {
                root,
                slot,
                parent,
                link: link(&root),
                own: [0; 3],
                total: [0; 3],
                unresolved_votes: 0,
            });
            self.indices.insert(root, node_index);
        }

        self.applied = vec![None; latest_messages.len()];
        self.balances = Some(balances);
        self.rules = rules;
        self.stale = None;
        self.dirty = true;

        let any_equivocators = !equivocating.is_empty();
        for (validator, message) in latest_messages.iter().enumerate() {
            let Some(message) = message else {
                continue;
            };
            let validator_index = validator as ValidatorIndex;
            if any_equivocators && equivocating.contains(&validator_index) {
                continue;
            }
            let Some(&node_index) = self.indices.get(&message.root) else {
                continue;
            };
            let landing = self.landing(node_index, message);
            self.move_vote(validator, Some(landing));
        }
    }

    /// Adds a block imported after the last rebuild. Ignored while stale, since
    /// the rebuild reads every block from the index, and for a root the array
    /// already holds.
    pub(crate) fn insert_node(
        &mut self,
        root: H256,
        slot: Slot,
        parent_root: H256,
        link: BlockPayloadLink,
    ) {
        if self.stale.is_some() || self.indices.contains_key(&root) {
            return;
        }
        let parent = self.indices.get(&parent_root).copied();
        let node_index = u32::try_from(self.nodes.len()).expect("node count fits u32");
        self.nodes.push(Node {
            root,
            slot,
            parent,
            link: Some(link),
            own: [0; 3],
            total: [0; 3],
            unresolved_votes: 0,
        });
        self.indices.insert(root, node_index);
    }

    /// One vote batch: `validators` all now have `message` as their latest
    /// message. The caller has already left out equivocators and validators
    /// whose existing message is fresher.
    pub(crate) fn apply_votes(&mut self, validators: &[ValidatorIndex], message: &LatestMessage) {
        if self.stale.is_some() || validators.is_empty() {
            return;
        }
        let landing = self
            .indices
            .get(&message.root)
            .map(|&node_index| self.landing(node_index, message));
        for &validator in validators {
            let validator = usize::try_from(validator).expect("validator index fits usize");
            self.move_vote(validator, landing);
        }
    }

    /// `validator`'s vote no longer counts anywhere (it equivocated).
    pub(crate) fn remove_vote(&mut self, validator: ValidatorIndex) {
        if self.stale.is_some() {
            return;
        }
        let validator = usize::try_from(validator).expect("validator index fits usize");
        self.move_vote(validator, None);
    }

    /// Where `message` lands on the block at `node_index`: the specification's
    /// `get_supported_node`. A vote from the block's own slot supports the
    /// block before its payload is decided; a later one names a branch, which
    /// before gloas (or for a pre-gloas block) is always the full one.
    fn landing(&self, node_index: u32, message: &LatestMessage) -> Applied {
        let node = &self.nodes[node_index as usize];
        if node.slot >= message.slot {
            return Applied {
                node: node_index,
                status: PayloadStatus::Pending,
                unresolved: false,
            };
        }
        match self.effective_link(node) {
            Some(link) => Applied {
                node: node_index,
                status: if !link.is_gloas() || message.payload_present {
                    PayloadStatus::Full
                } else {
                    PayloadStatus::Empty
                },
                unresolved: false,
            },
            None => Applied {
                node: node_index,
                status: PayloadStatus::Pending,
                unresolved: true,
            },
        }
    }

    fn effective_link(&self, node: &Node) -> Option<BlockPayloadLink> {
        match self.rules {
            WeightRules::PreGloas => Some(BlockPayloadLink::PreGloas),
            WeightRules::Gloas => node.link,
        }
    }

    fn balance(&self, validator: usize) -> Gwei {
        self.balances
            .as_ref()
            .map_or(0, |balances| balances.get(validator as ValidatorIndex))
    }

    /// Moves `validator`'s counted vote to `target` (`None`: counted nowhere).
    /// A zero balance counts nowhere either, as in the tally.
    fn move_vote(&mut self, validator: usize, target: Option<Applied>) {
        let balance = self.balance(validator);
        let target = target.filter(|_| balance > 0);
        let current = self.applied.get(validator).copied().flatten();
        if current == target {
            return;
        }
        if let Some(current) = current {
            let node = &mut self.nodes[current.node as usize];
            let weight = &mut node.own[slot_of(current.status)];
            match weight.checked_sub(balance) {
                Some(rest) => *weight = rest,
                None => {
                    warn!(
                        validator,
                        balance,
                        weight = *weight,
                        "Fork-choice weight would go below zero; rebuilding the cached weights"
                    );
                    *weight = 0;
                    self.stale = Some(RebuildReason::Underflow);
                }
            }
            if current.unresolved {
                node.unresolved_votes = node.unresolved_votes.saturating_sub(1);
            }
        }
        if let Some(target) = target {
            let node = &mut self.nodes[target.node as usize];
            let weight = &mut node.own[slot_of(target.status)];
            *weight = weight.saturating_add(balance);
            if target.unresolved {
                node.unresolved_votes += 1;
            }
        }
        if self.applied.len() <= validator {
            self.applied.resize(validator + 1, None);
        }
        self.applied[validator] = target;
        self.dirty = true;
    }

    /// Picks up payload links recorded since the nodes were built, for nodes
    /// that had none. Call before [`Self::rebuild_reason`]: votes already
    /// counted on such a node are left to the rebuild it then asks for
    /// (`Link`).
    pub(crate) fn fill_missing_links(
        &mut self,
        payload_links: &HashMap<H256, (Slot, BlockPayloadLink)>,
    ) {
        for node in &mut self.nodes {
            if node.link.is_none()
                && let Some(&(_, link)) = payload_links.get(&node.root)
            {
                node.link = Some(link);
                self.dirty = true;
            }
        }
    }

    /// Recomputes every `total` from `own`, if a vote moved since the last
    /// refresh: one pass from the newest node back to the oldest, each node
    /// handing its `PENDING` total to the parent branch it builds on.
    pub(crate) fn refresh(&mut self) {
        if !self.dirty {
            return;
        }
        for node in &mut self.nodes {
            node.total = node.own;
        }
        for node_index in (0..self.nodes.len()).rev() {
            let node = &mut self.nodes[node_index];
            node.total[PENDING] = node.total[PENDING]
                .saturating_add(node.total[EMPTY])
                .saturating_add(node.total[FULL]);
            let (pending, parent, link) = (node.total[PENDING], node.parent, node.link);
            let Some(parent) = parent else {
                continue;
            };
            let link = match self.rules {
                WeightRules::PreGloas => Some(BlockPayloadLink::PreGloas),
                WeightRules::Gloas => link,
            };
            let Some(parent_status) = link.and_then(BlockPayloadLink::parent_status) else {
                continue;
            };
            let bucket = &mut self.nodes[parent as usize].total[slot_of(parent_status)];
            *bucket = bucket.saturating_add(pending);
        }
        self.dirty = false;
    }

    /// The refreshed totals of every node at or above `bound` that `index`
    /// holds, zero totals left out, keyed as the head walk reads them.
    ///
    /// Fails exactly where the tally fails for the same inputs: a block in the
    /// window holds votes that need its unknown payload link, or has weight for
    /// a parent in the window that its link cannot place.
    pub(crate) fn weights(
        &self,
        index: &HashMap<H256, (Slot, H256)>,
        bound: Slot,
    ) -> Result<HashMap<ForkChoiceNode, Gwei>, ProtoArrayError> {
        debug_assert!(
            self.stale.is_none() && !self.dirty,
            "read a refreshed array"
        );
        let in_window = |node: &Node| node.slot >= bound && index.contains_key(&node.root);
        let mut weights = HashMap::with_capacity(self.nodes.len() * 2);
        for node in &self.nodes {
            if !in_window(node) {
                continue;
            }
            if node.unresolved_votes > 0 {
                return Err(ProtoArrayError::MissingLink(node.root));
            }
            if node.total[PENDING] != 0
                && let Some(parent) = node.parent
                && in_window(&self.nodes[parent as usize])
            {
                match self.effective_link(node) {
                    None => return Err(ProtoArrayError::MissingLink(node.root)),
                    Some(link) if link.parent_status().is_none() => {
                        return Err(ProtoArrayError::MissingParentStatus(node.root));
                    }
                    Some(_) => {}
                }
            }
            for payload_status in [
                PayloadStatus::Pending,
                PayloadStatus::Empty,
                PayloadStatus::Full,
            ] {
                let weight = node.total[slot_of(payload_status)];
                if weight != 0 {
                    weights.insert(
                        ForkChoiceNode {
                            root: node.root,
                            payload_status,
                        },
                        weight,
                    );
                }
            }
        }
        Ok(weights)
    }

    /// Compares this array, refreshed, with one rebuilt from the same inputs,
    /// node by node and vote by vote, keyed by root since the two can order
    /// their nodes differently. For tests: the incremental path must leave the
    /// array exactly where a rebuild would.
    pub(crate) fn diff_against_rebuild(
        &self,
        index: &HashMap<H256, (Slot, H256)>,
        link: impl Fn(&H256) -> Option<BlockPayloadLink>,
        latest_messages: &[Option<LatestMessage>],
        equivocating: &HashSet<ValidatorIndex>,
    ) -> Result<(), String> {
        if self.stale.is_some() {
            return Err("the array is stale, so there is nothing incremental to compare".into());
        }
        let balances = self.balances.clone().expect("a built array has balances");
        let mut current = self.clone();
        current.refresh();
        let mut rebuilt = ProtoArray::default();
        rebuilt.rebuild(
            index,
            link,
            latest_messages,
            equivocating,
            balances,
            self.rules,
        );
        rebuilt.refresh();

        let by_root = |array: &ProtoArray| -> HashMap<H256, ComparedNode> {
            array
                .nodes
                .iter()
                .map(|node| {
                    let compared = ComparedNode {
                        slot: node.slot,
                        parent: node.parent.map(|parent| array.nodes[parent as usize].root),
                        own: node.own,
                        total: node.total,
                        unresolved_votes: node.unresolved_votes,
                    };
                    (node.root, compared)
                })
                .collect()
        };
        let (current_nodes, rebuilt_nodes) = (by_root(&current), by_root(&rebuilt));
        if current_nodes != rebuilt_nodes {
            return Err(format!(
                "nodes differ:\nincremental {current_nodes:?}\nrebuilt     {rebuilt_nodes:?}"
            ));
        }

        let votes = |array: &ProtoArray| -> Vec<Option<(H256, PayloadStatus, bool)>> {
            let mut votes: Vec<_> = array
                .applied
                .iter()
                .map(|applied| {
                    applied.map(|applied| {
                        (
                            array.nodes[applied.node as usize].root,
                            applied.status,
                            applied.unresolved,
                        )
                    })
                })
                .collect();
            while votes.last() == Some(&None) {
                votes.pop();
            }
            votes
        };
        let (current_votes, rebuilt_votes) = (votes(&current), votes(&rebuilt));
        if current_votes != rebuilt_votes {
            return Err(format!(
                "counted votes differ:\nincremental {current_votes:?}\nrebuilt     {rebuilt_votes:?}"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ethlambda_types::beacon::containers::Checkpoint;
    use proptest::prelude::*;

    use super::*;

    const VALIDATORS: usize = 10;

    fn root(byte: u8) -> H256 {
        H256([byte; 32])
    }

    fn balances(values: &[Gwei]) -> Arc<JustifiedBalances> {
        let total = values.iter().sum::<Gwei>().max(1);
        let increments = vec![0u16; values.len()].into();
        Arc::new(JustifiedBalances::new(
            Checkpoint::default(),
            values.to_vec().into(),
            total,
            increments,
            Box::default(),
            total,
        ))
    }

    /// The store-side state the array follows, kept by the test the way
    /// `Store` keeps it, plus a naive reference computation of the weights.
    struct World {
        /// root -> (slot, parent_root, link), the block index plus links.
        blocks: HashMap<H256, (Slot, H256, BlockPayloadLink)>,
        latest_messages: Vec<Option<LatestMessage>>,
        equivocating: HashSet<ValidatorIndex>,
        balances: Arc<JustifiedBalances>,
        rules: WeightRules,
        array: ProtoArray,
    }

    impl World {
        fn new() -> Self {
            let mut blocks = HashMap::new();
            blocks.insert(root(1), (0, H256::ZERO, BlockPayloadLink::PreGloas));
            World {
                blocks,
                latest_messages: vec![None; VALIDATORS],
                equivocating: HashSet::new(),
                balances: balances(&[32; VALIDATORS]),
                rules: WeightRules::Gloas,
                array: ProtoArray::default(),
            }
        }

        fn index(&self) -> HashMap<H256, (Slot, H256)> {
            self.blocks
                .iter()
                .map(|(&root, &(slot, parent, _))| (root, (slot, parent)))
                .collect()
        }

        fn links(&self) -> HashMap<H256, (Slot, BlockPayloadLink)> {
            self.blocks
                .iter()
                .map(|(&root, &(slot, _, link))| (root, (slot, link)))
                .collect()
        }

        /// What the store's read does: rebuild if needed, refresh, copy out.
        fn read(&mut self) -> HashMap<ForkChoiceNode, Gwei> {
            let index = self.index();
            let links = self.links();
            self.array.fill_missing_links(&links);
            if self
                .array
                .rebuild_reason(&index, &self.balances, self.rules)
                .is_some()
            {
                self.array.rebuild(
                    &index,
                    |root| links.get(root).map(|&(_, link)| link),
                    &self.latest_messages,
                    &self.equivocating,
                    Arc::clone(&self.balances),
                    self.rules,
                );
            }
            self.array.refresh();
            self.array.weights(&index, 0).expect("every link is known")
        }

        /// The tally and fold `compute_node_weights` performs, without the
        /// bound or the boost.
        fn reference(&self) -> HashMap<ForkChoiceNode, Gwei> {
            let link = |root: &H256| match self.rules {
                WeightRules::PreGloas => BlockPayloadLink::PreGloas,
                WeightRules::Gloas => self.blocks[root].2,
            };
            let mut weights: HashMap<ForkChoiceNode, Gwei> = HashMap::new();
            for (validator, message) in self.latest_messages.iter().enumerate() {
                let Some(message) = message else { continue };
                if self.equivocating.contains(&(validator as u64)) {
                    continue;
                }
                let balance = self.balances.get(validator as u64);
                let Some(&(block_slot, _, _)) = self.blocks.get(&message.root) else {
                    continue;
                };
                if balance == 0 {
                    continue;
                }
                let payload_status = if block_slot < message.slot {
                    if !link(&message.root).is_gloas() || message.payload_present {
                        PayloadStatus::Full
                    } else {
                        PayloadStatus::Empty
                    }
                } else {
                    PayloadStatus::Pending
                };
                *weights
                    .entry(ForkChoiceNode {
                        root: message.root,
                        payload_status,
                    })
                    .or_default() += balance;
            }
            let mut order: Vec<(Slot, H256, H256)> = self
                .blocks
                .iter()
                .map(|(&root, &(slot, parent, _))| (slot, root, parent))
                .collect();
            order.sort_unstable_by_key(|block| std::cmp::Reverse(block.0));
            for (_, root, parent) in order {
                let total: Gwei = [
                    PayloadStatus::Pending,
                    PayloadStatus::Empty,
                    PayloadStatus::Full,
                ]
                .into_iter()
                .map(|payload_status| {
                    weights
                        .get(&ForkChoiceNode {
                            root,
                            payload_status,
                        })
                        .copied()
                        .unwrap_or_default()
                })
                .sum();
                if total == 0 {
                    continue;
                }
                weights.insert(
                    ForkChoiceNode {
                        root,
                        payload_status: PayloadStatus::Pending,
                    },
                    total,
                );
                if self.blocks.contains_key(&parent) {
                    let parent_status = link(&root).parent_status().expect("known parent status");
                    *weights
                        .entry(ForkChoiceNode {
                            root: parent,
                            payload_status: parent_status,
                        })
                        .or_default() += total;
                }
            }
            weights.retain(|_, weight| *weight != 0);
            weights
        }

        fn apply(&mut self, op: &Op) {
            match *op {
                Op::Block {
                    parent,
                    gap,
                    gloas,
                    on_full,
                } => {
                    let mut roots: Vec<H256> = self.blocks.keys().copied().collect();
                    roots.sort_unstable();
                    let parent_root = roots[parent % roots.len()];
                    let slot = self.blocks[&parent_root].0 + gap;
                    let new_root = root(self.blocks.len() as u8 + 1);
                    let link = if gloas {
                        BlockPayloadLink::Gloas {
                            parent_status: Some(if on_full {
                                PayloadStatus::Full
                            } else {
                                PayloadStatus::Empty
                            }),
                        }
                    } else {
                        BlockPayloadLink::PreGloas
                    };
                    // `on_block`'s order: the node, then the row.
                    self.array.insert_node(new_root, slot, parent_root, link);
                    self.blocks.insert(new_root, (slot, parent_root, link));
                }
                Op::Votes {
                    mask,
                    block,
                    later,
                    payload_present,
                } => {
                    let mut roots: Vec<H256> = self.blocks.keys().copied().collect();
                    roots.sort_unstable();
                    let target = roots[block % roots.len()];
                    let message = LatestMessage {
                        epoch: 0,
                        slot: self.blocks[&target].0 + later,
                        root: target,
                        payload_present,
                    };
                    // `Store::record_latest_messages` with the gloas ordering.
                    let mut changed = Vec::new();
                    for validator in 0..VALIDATORS {
                        if mask & (1 << validator) == 0
                            || self.equivocating.contains(&(validator as u64))
                        {
                            continue;
                        }
                        let replace = self.latest_messages[validator]
                            .is_none_or(|existing| message.slot > existing.slot);
                        if replace {
                            self.latest_messages[validator] = Some(message);
                            changed.push(validator as u64);
                        }
                    }
                    self.array.apply_votes(&changed, &message);
                }
                Op::Equivocate { validator } => {
                    let validator = (validator % VALIDATORS) as u64;
                    self.equivocating.insert(validator);
                    self.array.remove_vote(validator);
                }
                Op::Balances { seed } => {
                    let values: Vec<Gwei> = (0..VALIDATORS as u64)
                        .map(|validator| (seed.wrapping_mul(validator + 7) >> 3) % 5 * 8)
                        .collect();
                    self.balances = balances(&values);
                }
                Op::Rules { gloas } => {
                    self.rules = if gloas {
                        WeightRules::Gloas
                    } else {
                        WeightRules::PreGloas
                    };
                }
                Op::Stale => self.array.mark_stale(RebuildReason::Removal),
                Op::Read => {}
            }
        }
    }

    #[derive(Debug, Clone)]
    enum Op {
        Block {
            parent: usize,
            gap: u64,
            gloas: bool,
            on_full: bool,
        },
        Votes {
            mask: u16,
            block: usize,
            later: u64,
            payload_present: bool,
        },
        Equivocate {
            validator: usize,
        },
        Balances {
            seed: u64,
        },
        Rules {
            gloas: bool,
        },
        Stale,
        Read,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            4 => (any::<usize>(), 1..4u64, any::<bool>(), any::<bool>()).prop_map(
                |(parent, gap, gloas, on_full)| Op::Block { parent, gap, gloas, on_full }
            ),
            8 => (any::<u16>(), any::<usize>(), 0..3u64, any::<bool>()).prop_map(
                |(mask, block, later, payload_present)| Op::Votes { mask, block, later, payload_present }
            ),
            1 => any::<usize>().prop_map(|validator| Op::Equivocate { validator }),
            1 => any::<u64>().prop_map(|seed| Op::Balances { seed }),
            1 => any::<bool>().prop_map(|gloas| Op::Rules { gloas }),
            1 => Just(Op::Stale),
            3 => Just(Op::Read),
        ]
    }

    proptest! {
        /// After every operation the cached weights equal the reference tally,
        /// and the incrementally kept array equals a fresh rebuild.
        #[test]
        fn cached_weights_match_a_fresh_tally(ops in proptest::collection::vec(op(), 1..60)) {
            let mut world = World::new();
            world.read();
            for op in &ops {
                world.apply(op);
                // The incremental state, before the read can rebuild it. The
                // rebuild it is compared with uses the array's own balances
                // and rules, so a pending balance or rule change does not
                // excuse a difference.
                if world.array.stale.is_none() {
                    let index = world.index();
                    let links = world.links();
                    world
                        .array
                        .diff_against_rebuild(
                            &index,
                            |root| links.get(root).map(|&(_, link)| link),
                            &world.latest_messages,
                            &world.equivocating,
                        )
                        .map_err(|err| TestCaseError::fail(format!("after {op:?}: {err}")))?;
                }
                let cached = world.read();
                prop_assert_eq!(cached, world.reference(), "after {:?}", op);
            }
        }
    }

    #[test]
    fn a_fresh_array_is_stale_and_ignores_votes() {
        let mut array = ProtoArray::default();
        let message = LatestMessage {
            epoch: 0,
            slot: 1,
            root: root(1),
            payload_present: false,
        };
        array.apply_votes(&[0, 1], &message);
        array.insert_node(root(2), 1, root(1), BlockPayloadLink::PreGloas);
        assert!(array.nodes.is_empty());
        assert!(array.applied.is_empty());
        assert_eq!(array.stale, Some(RebuildReason::Unbuilt));
    }

    #[test]
    fn a_vote_moving_between_branches_moves_its_weight() {
        let mut world = World::new();
        world.apply(&Op::Block {
            parent: 0,
            gap: 1,
            gloas: true,
            on_full: true,
        });
        world.read();
        let child = root(2);
        let vote = |later, payload_present| Op::Votes {
            mask: 0b1,
            block: 1,
            later,
            payload_present,
        };
        world.apply(&vote(1, false));
        let weights = world.read();
        assert_eq!(
            weights.get(&ForkChoiceNode {
                root: child,
                payload_status: PayloadStatus::Empty
            }),
            Some(&32)
        );
        // A later message for the full branch: same root, one slot on.
        world.apply(&vote(2, true));
        let weights = world.read();
        assert_eq!(weights, world.reference());
        assert_eq!(
            weights.get(&ForkChoiceNode {
                root: child,
                payload_status: PayloadStatus::Full
            }),
            Some(&32)
        );
        assert!(!weights.contains_key(&ForkChoiceNode {
            root: child,
            payload_status: PayloadStatus::Empty
        }));
        // The child builds on the anchor's full branch.
        assert_eq!(
            weights.get(&ForkChoiceNode {
                root: root(1),
                payload_status: PayloadStatus::Full
            }),
            Some(&32)
        );
    }

    #[test]
    fn an_underflow_marks_the_array_for_a_rebuild() {
        let mut world = World::new();
        world.read();
        world.apply(&Op::Votes {
            mask: 0b1,
            block: 0,
            later: 0,
            payload_present: false,
        });
        // Corrupt the count the way only a bug could.
        world.array.nodes[0].own[PENDING] = 0;
        world.array.remove_vote(0);
        assert_eq!(world.array.stale, Some(RebuildReason::Underflow));
        world.equivocating.insert(0);
        assert_eq!(world.read(), world.reference());
    }

    #[test]
    fn a_vote_needing_an_unknown_link_fails_the_read_only_inside_the_window() {
        let mut array = ProtoArray::default();
        let mut index = HashMap::new();
        index.insert(root(1), (0, H256::ZERO));
        index.insert(root(2), (5, root(1)));
        let message = LatestMessage {
            epoch: 0,
            slot: 6,
            root: root(2),
            payload_present: true,
        };
        array.rebuild(
            &index,
            |_| None,
            &[Some(message)],
            &HashSet::new(),
            balances(&[32]),
            WeightRules::Gloas,
        );
        array.refresh();
        assert_eq!(
            array.weights(&index, 0),
            Err(ProtoArrayError::MissingLink(root(2)))
        );
        // Above the block: nothing in the window needs the link.
        assert!(array.weights(&index, 6).unwrap().is_empty());

        // Once the link is recorded, the read asks for a rebuild and then
        // places the vote on its branch.
        let mut links = HashMap::new();
        links.insert(
            root(2),
            (
                5,
                BlockPayloadLink::Gloas {
                    parent_status: Some(PayloadStatus::Empty),
                },
            ),
        );
        array.fill_missing_links(&links);
        let snapshot = Arc::clone(array.balances.as_ref().unwrap());
        assert_eq!(
            array.rebuild_reason(&index, &snapshot, WeightRules::Gloas),
            Some(RebuildReason::Link)
        );
    }
}
