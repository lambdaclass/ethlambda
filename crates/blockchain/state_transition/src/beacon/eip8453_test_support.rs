//! Test scaffolding for the EIP-8453 host: a beacon store anchored at an
//! EIP-8453 block whose state has real signing keys, with the shared fork
//! choice node installed at that anchor, plus signing helpers for head votes
//! and single attestations.

use std::sync::Arc;

use ethlambda_storage::backend::InMemoryBackend;

use crate::beacon::config::Config;
use crate::beacon::constants::{DOMAIN_FINALITY_ATTESTER, DOMAIN_HEAD_VOTE};
use crate::beacon::containers::shared::BeaconBlockHeader;
use crate::beacon::containers::{BeaconState, SignedBeaconBlock, eip8453};
use crate::beacon::eip8453_fork_choice::{anchor, new_engine};
use crate::beacon::eip8453_node::{Eip8453Node, SharedEip8453Node};
use crate::beacon::fork::ForkName;
use crate::beacon::fork_choice::{self, Store};
use crate::beacon::helpers::accessors::get_domain;
use crate::beacon::helpers::eip8453::{
    compute_attestation_committee_slot, compute_round_at_slot, get_attestation_committee,
};
use crate::beacon::helpers::misc::{compute_epoch_at_slot, compute_signing_root};
use crate::beacon::helpers::test_state;
use crate::beacon::preset;
use crate::beacon::primitives::{Epoch, HashTreeRoot as _, Root, Slot, ValidatorIndex};

/// Genesis time of the scene's network, in seconds.
pub const GENESIS_TIME: u64 = 1_000;

/// An anchored EIP-8453 store and its fork choice node.
pub struct Scene {
    pub store: Store,
    pub node: SharedEip8453Node,
    pub config: Config,
    pub anchor_root: Root,
    pub anchor_slot: Slot,
    pub state: Arc<BeaconState>,
}

/// The fork schedule the scene runs: gloas and heze at genesis, EIP-8453 at
/// epoch 1, the scene's anchor epoch.
pub fn config() -> Config {
    let mut config = Config::active()
        .with_fork_epoch(ForkName::Altair, 0)
        .with_fork_epoch(ForkName::Bellatrix, 0)
        .with_fork_epoch(ForkName::Capella, 0)
        .with_fork_epoch(ForkName::Deneb, 0)
        .with_fork_epoch(ForkName::Electra, 0)
        .with_fork_epoch(ForkName::Fulu, 0)
        .with_fork_epoch(ForkName::Gloas, 0)
        .with_fork_epoch(ForkName::Heze, 0)
        .with_fork_epoch(ForkName::Eip8453, 1);
    config.genesis_time = GENESIS_TIME;
    config
}

/// A store anchored at an EIP-8453 block at the first slot of epoch 1, over
/// `validators` validators with real keys, and the node anchored with it.
pub fn scene(validators: usize) -> Scene {
    let config = config();
    let mut state = test_state::with_signing_validators_at(ForkName::Eip8453, validators);
    *state.genesis_time_mut() = GENESIS_TIME;
    let slot = state.slot();
    // Every sync committee seat held by a registered key, and the anchor's
    // payload not delivered (its bid's block hash is not the state's latest),
    // so a child builds on its EMPTY branch with a self-built bid.
    let pubkeys: Vec<_> = state.iter_validators().map(|v| v.pubkey).collect();
    let mut body = eip8453::BeaconBlockBody::empty();
    if let BeaconState::Eip8453(inner) = &mut state {
        for (seat, pubkey) in inner.current_sync_committee.pubkeys.iter_mut().enumerate() {
            *pubkey = pubkeys[seat % pubkeys.len()];
        }
        inner.next_sync_committee = inner.current_sync_committee.clone();
        inner.latest_execution_payload_bid.block_hash =
            crate::beacon::primitives::Bytes32::repeat_byte(0xaa);
        body.signed_execution_payload_bid.message = inner.latest_execution_payload_bid.clone();
    }
    *state.latest_block_header_mut() = BeaconBlockHeader {
        slot,
        proposer_index: 0,
        parent_root: Root::repeat_byte(0xaa),
        state_root: Root::ZERO,
        body_root: body.hash_tree_root(),
    };
    let state_root = state.hash_tree_root();
    let block = SignedBeaconBlock::Eip8453(eip8453::SignedBeaconBlock {
        message: eip8453::BeaconBlock {
            slot,
            proposer_index: 0,
            parent_root: Root::repeat_byte(0xaa),
            state_root,
            body,
        },
        signature: Default::default(),
    });
    let anchor_root = block.message_hash_tree_root();
    let store =
        fork_choice::get_forkchoice_store(Arc::new(InMemoryBackend::new()), state, block, &config)
            .expect("an EIP-8453 anchor builds a store");
    let state = store
        .get_state(&anchor_root)
        .expect("get")
        .expect("the anchor's state is stored");
    let engine = new_engine(anchor(anchor_root, slot, &state).expect("the anchor is its target"));
    let node = SharedEip8453Node::new();
    node.install(Eip8453Node::new(store.config().as_ref().clone(), engine));
    Scene {
        store,
        node,
        config,
        anchor_root,
        anchor_slot: slot,
        state,
    }
}

impl Scene {
    /// Unix milliseconds `offset_ms` into `slot`.
    pub fn at(&self, slot: Slot, offset_ms: u64) -> u64 {
        self.config
            .time_at_slot_ms(self.config.genesis_time_ms(), slot)
            + offset_ms
    }

    /// The head vote committee of `slot` in the anchor state.
    pub fn committee(&self, slot: Slot) -> Vec<ValidatorIndex> {
        crate::beacon::eip8453_fork_choice::head_vote_committee(&self.state, slot, &self.config)
            .expect("the anchor state answers its own epoch")
    }

    /// `validator`'s signed head vote for `data`.
    pub fn head_vote(
        &self,
        validator: ValidatorIndex,
        data: eip8453::HeadVoteData,
    ) -> eip8453::HeadVoteMessage {
        let domain = get_domain(
            &self.state,
            DOMAIN_HEAD_VOTE,
            Some(compute_epoch_at_slot(data.slot)),
        );
        let signing_root = compute_signing_root(data.hash_tree_root(), domain);
        eip8453::HeadVoteMessage {
            validator_index: validator,
            data,
            signature: test_state::sign_for(validator as usize, signing_root),
        }
    }

    /// A non-empty attestation committee whose slot is `slot`, and its
    /// members: `(committee_index, members)`.
    pub fn attestation_committee_at(&self, slot: Slot) -> (u64, Vec<ValidatorIndex>) {
        let round = compute_round_at_slot(slot);
        let epoch = compute_epoch_at_slot(slot);
        (0..preset::ATTESTATION_COMMITTEES_PER_ROUND as u64)
            .filter(|&index| compute_attestation_committee_slot(round, index).unwrap() == slot)
            .map(|index| {
                let members: Vec<ValidatorIndex> =
                    get_attestation_committee(&self.state, epoch, index)
                        .unwrap()
                        .iter()
                        .copied()
                        .collect();
                (index, members)
            })
            .find(|(_, members)| !members.is_empty())
            .expect("some committee of the slot has a member")
    }

    /// A signed EIP-8453 block at `slot` on the anchor, on its EMPTY branch,
    /// carrying `head_votes` and `head_vote_support` (applied as given, so a
    /// test may pass a malformed body; the state root then stays zero).
    pub fn child_block(
        &self,
        slot: Slot,
        head_votes: Vec<eip8453::HeadVote>,
        head_vote_support: Vec<eip8453::HeadVoteSupportBits>,
    ) -> SignedBeaconBlock {
        use crate::beacon::constants::{
            BUILDER_INDEX_SELF_BUILD, DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO,
        };
        use crate::beacon::helpers::accessors::{get_beacon_proposer_index, get_randao_mix};
        let mut state = (*self.state).clone();
        crate::beacon::stf::process_slots(&mut state, slot, &self.config).unwrap();
        let epoch = compute_epoch_at_slot(slot);
        let proposer = get_beacon_proposer_index(&state).unwrap();
        let sign = |root: Root, domain_type| {
            let domain = get_domain(&state, domain_type, Some(epoch));
            test_state::sign_for(proposer as usize, compute_signing_root(root, domain))
        };
        let randao = sign(epoch.hash_tree_root(), DOMAIN_RANDAO);
        let mut bid = crate::beacon::containers::gloas::SignedExecutionPayloadBid::default();
        bid.message.builder_index = BUILDER_INDEX_SELF_BUILD;
        bid.message.slot = slot;
        bid.message.parent_block_hash = *state.latest_block_hash().unwrap();
        bid.message.block_hash = crate::beacon::primitives::Bytes32::repeat_byte(0x33);
        bid.message.parent_block_root = self.anchor_root;
        bid.message.prev_randao = get_randao_mix(&state, epoch);
        bid.message.inclusion_list_bits =
            Some(crate::beacon::containers::heze::InclusionListBits::new());
        bid.signature =
            crate::beacon::primitives::BlsSignature(crate::beacon::bls::G2_POINT_AT_INFINITY);
        let assembled = crate::beacon::eip8453_block_production::assemble_block(
            &state,
            self.anchor_root,
            slot,
            randao,
            bid.clone(),
            head_votes.clone(),
            head_vote_support.clone(),
            Vec::new(),
            &self.config,
        );
        let block = match assembled {
            Ok((block, _)) => block,
            Err(_) => {
                let mut body = eip8453::BeaconBlockBody::empty();
                body.randao_reveal = randao;
                body.signed_execution_payload_bid = bid;
                body.head_votes = head_votes.into();
                body.head_vote_support = head_vote_support.into();
                eip8453::BeaconBlock {
                    slot,
                    proposer_index: proposer,
                    parent_root: self.anchor_root,
                    state_root: Root::ZERO,
                    body,
                }
            }
        };
        let signature = sign(block.hash_tree_root(), DOMAIN_BEACON_PROPOSER);
        SignedBeaconBlock::Eip8453(eip8453::SignedBeaconBlock {
            message: block,
            signature,
        })
    }

    /// `attester`'s signed single attestation of `data` for committee
    /// `committee_index` of `epoch`.
    pub fn attestation(
        &self,
        attester: ValidatorIndex,
        committee_index: u64,
        epoch: Epoch,
        data: eip8453::AttestationData,
    ) -> eip8453::SingleAttestation {
        let domain = get_domain(&self.state, DOMAIN_FINALITY_ATTESTER, Some(epoch));
        let signing_root = compute_signing_root(data.hash_tree_root(), domain);
        eip8453::SingleAttestation {
            committee_index,
            attester_index: attester,
            data,
            signature: test_state::sign_for(attester as usize, signing_root),
            epoch,
        }
    }
}
