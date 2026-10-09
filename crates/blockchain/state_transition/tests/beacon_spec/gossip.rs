//! The `networking/gossip_*` runners: the specification's gossip validation
//! vectors (`tests/formats/networking/gossip_validation.md` in
//! consensus-specs), run against `beacon::gossip`.
//!
//! These used to come from a separate, newer-release fixture tree of their
//! own; v1.7.0-beta.2's main tree now ships the same vectors under
//! `networking/gossip_*` alongside every other runner, so they are collected
//! from there like any other handler (see [`super::collect`]). `networking.rs`
//! filters these same directories out of its own collection, so the two
//! runners partition the tree rather than both claiming it.

use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::sync::Arc;

use ethlambda_state_transition::beacon::ForkName;
use ethlambda_state_transition::beacon::builder_market::BuilderMarket;
use ethlambda_state_transition::beacon::config::Config;
use ethlambda_state_transition::beacon::containers::{
    BeaconState, Checkpoint, DataColumnSidecar, SignedAggregateAndProof, SignedBeaconBlock, altair,
    electra, gloas, heze, phase0,
};
use ethlambda_state_transition::beacon::fork_choice::{
    self, DataAvailability, PayloadStatusEnum, PayloadValidity, Store,
};
use ethlambda_state_transition::beacon::gossip::operations::SeenOperations;
use ethlambda_state_transition::beacon::gossip::{
    self as rules, Outcome, SeenAggregates, SeenAttestations, SeenBlockColumns, SeenBlocks,
    SeenColumns, SeenEnvelopes, SeenInclusionLists, SeenPayloadAttestations,
    SeenSyncCommitteeMessages, SeenSyncContributions,
};
use ethlambda_state_transition::beacon::helpers::accessors::CommitteeCache;
use ethlambda_state_transition::beacon::inclusion_list::is_inclusion_list_timely;
use ethlambda_state_transition::beacon::primitives::Root;
use ethlambda_state_transition::beacon::stf::ExecutionEngine;
use ethlambda_storage::ForkCheckpoints;
use ethlambda_types::beacon::containers::{capella, shared};
use ethlambda_types::beacon::operation::BeaconOperation;
use libssz::SszDecode;
use libtest_mimic::{Failed, Trial};

use super::{Case, PRESET, collect, collect_all_handlers};

/// The handlers this runner covers, and runs.
const HANDLERS: &[&str] = &[
    "gossip_beacon_block",
    "gossip_data_column_sidecar",
    "gossip_beacon_aggregate_and_proof",
    "gossip_beacon_attestation",
    "gossip_execution_payload_envelope",
    "gossip_payload_attestation_message",
    "gossip_voluntary_exit",
    "gossip_proposer_slashing",
    "gossip_attester_slashing",
    "gossip_bls_to_execution_change",
    "gossip_sync_committee_message",
    "gossip_sync_committee_contribution_and_proof",
    "gossip_execution_payload_bid",
    "gossip_proposer_preferences",
    "gossip_inclusion_list",
];

/// The forks each of [`HANDLERS`] validates. A case from any other fork is
/// reported as ignored rather than run, the same "known gap, not a silent one"
/// treatment `case.in_scope()` gives a fork past `HIGHEST_IMPLEMENTED_FORK`.
///
/// `case.in_scope()` alone would pass every fork up to gloas, since the state
/// transition handles them all; the gossip rules do not. The block rules
/// (`beacon::gossip::block`) and the column rules (`beacon::gossip::column`)
/// have both fulu's and gloas's, and so do the aggregate and attestation
/// rules (`beacon::gossip::{aggregate, attestation}`): electra's, which fulu
/// keeps, and gloas's payload-flag modification of them.
fn validated_forks(handler: &str) -> &'static [ForkName] {
    match handler {
        "gossip_data_column_sidecar" | "gossip_beacon_block" => {
            &[ForkName::Fulu, ForkName::Gloas, ForkName::Heze]
        }
        "gossip_beacon_aggregate_and_proof" | "gossip_beacon_attestation" => {
            &[ForkName::Fulu, ForkName::Gloas, ForkName::Heze]
        }
        "gossip_execution_payload_envelope"
        | "gossip_payload_attestation_message"
        | "gossip_execution_payload_bid"
        | "gossip_proposer_preferences" => &[ForkName::Gloas, ForkName::Heze],
        "gossip_inclusion_list" => &[ForkName::Heze],
        // `gossip::operations` validates electra-shaped operations against an
        // electra or fulu head state and ignores every other one, so gloas's
        // vectors (builder exits included) are a known gap rather than a run.
        "gossip_voluntary_exit"
        | "gossip_proposer_slashing"
        | "gossip_attester_slashing"
        | "gossip_bls_to_execution_change" => &[ForkName::Fulu],
        // Altair's rules, which neither fulu nor gloas changes.
        "gossip_sync_committee_message" | "gossip_sync_committee_contribution_and_proof" => {
            &[ForkName::Fulu, ForkName::Gloas, ForkName::Heze]
        }
        other => panic!("{other} is not in HANDLERS, so it has no validated forks"),
    }
}

/// Every other `gossip_*` handler the fixture tree ships, none of which this
/// node validates yet: the topics it neither subscribes to nor has a
/// validator for. Reported as ignored, named individually, rather than left
/// for `HANDLERS` to silently not mention, so the gap is visible in the test
/// list instead of inferred from an absence. [`trials`]'s accounting test
/// fails if a fixture release adds a `gossip_*` handler that is in neither
/// list, the same way [`super::UNMODELED_FORKS`] forces a decision on a new
/// fork directory.
///
/// Gloas's own topics (EIP-7732 ePBS) are all in [`HANDLERS`] now: the
/// envelope, the payload attestation, the builder's bid and the proposer's
/// preferences.
const IGNORED_HANDLERS: &[&str] = &["gossip_blob_sidecar", "gossip_partial_data_column_sidecar"];

/// The topics whose vectors need [`rebase_stale_header`].
const OPERATION_TOPICS: &[&str] = &[
    "voluntary_exit",
    "proposer_slashing",
    "attester_slashing",
    "bls_to_execution_change",
];

/// Vectors that disagree with a deliberate deviation, by case name.
const SKIPPED: &[(&str, &str)] = &[
    (
        "gossip_beacon_block__reject_parent_consensus_failed_execution_not_verified",
        "a parent seen without a post-state is queued, not rejected, until a bad-block cache exists",
    ),
    (
        "gossip_beacon_block__reject_parent_failed_validation",
        "a parent seen without a post-state is queued, not rejected, until a bad-block cache exists",
    ),
    (
        "gossip_data_column_sidecar__reject_parent_failed_validation",
        "a parent seen without a post-state is queued, not rejected, until a bad-block cache exists",
    ),
    (
        "gossip_data_column_sidecar__reject_block_failed_validation",
        "a block seen without a post-state is queued, not rejected, until a bad-block cache exists",
    ),
    (
        "gossip_beacon_aggregate_and_proof__reject_block_failed_validation",
        "a vote block seen without a post-state is ignored, not rejected, until a bad-block cache exists",
    ),
    (
        "gossip_beacon_attestation__reject_block_failed_validation",
        "a vote block seen without a post-state is ignored, not rejected, until a bad-block cache exists",
    ),
    (
        "gossip_execution_payload_envelope__reject_block_failed_validation",
        "a block seen without a post-state is queued, not rejected, until a bad-block cache exists",
    ),
    (
        "gossip_payload_attestation_message__reject_block_failed_validation",
        "a vote block seen without a post-state is ignored, not rejected, until a bad-block cache exists",
    ),
];

/// Capacity for a case's seen caches. A case sends a handful of messages.
const SEEN_CAPACITY: usize = 64;

#[derive(serde::Deserialize)]
struct Meta {
    topic: String,
    #[serde(default)]
    blocks: Vec<StoreBlock>,
    finalized_checkpoint: Option<FinalizedOverride>,
    /// Read through [`Meta::base_ms`]: only the operation vectors may omit it.
    current_time_ms: Option<u64>,
    messages: Vec<GossipMessage>,
}

impl Meta {
    fn is_operation_topic(&self) -> bool {
        OPERATION_TOPICS.contains(&self.topic.as_str())
    }

    /// The case's clock. The state-only operation vectors omit it, and their
    /// clock is genesis; every other topic must say.
    fn base_ms(&self) -> Result<u64, String> {
        match self.current_time_ms {
            Some(ms) => Ok(ms),
            None if self.is_operation_topic() => Ok(0),
            None => Err("meta.yaml lacks current_time_ms".into()),
        }
    }

    /// The clock reading `message` arrives at, in milliseconds since genesis
    /// (see [`GossipMessage::arrival_ms`]). The operation vectors may omit
    /// the message's timing too, and then arrive at the case clock; every
    /// other topic must name it.
    fn arrival_ms(&self, message: &GossipMessage) -> Result<u64, String> {
        let base_ms = self.base_ms()?;
        let untimed = message.offset_ms.is_none() && message.current_time_ms.is_none();
        if untimed && self.is_operation_topic() {
            return Ok(base_ms);
        }
        message.arrival_ms(base_ms)
    }
}

#[derive(serde::Deserialize)]
struct StoreBlock {
    block: String,
    #[serde(default)]
    failed: bool,
    #[serde(default)]
    pending: bool,
    payload_status: Option<String>,
    /// The block's execution payload envelope, delivered once the block is
    /// imported so `is_payload_verified` answers true for its root.
    payload: Option<String>,
}

#[derive(serde::Deserialize)]
struct FinalizedOverride {
    epoch: u64,
    root: Option<String>,
    block: Option<String>,
}

#[derive(serde::Deserialize)]
struct GossipMessage {
    /// The format's offset from `meta.current_time_ms`. Some of gloas's
    /// column vectors carry `current_time_ms` instead; see
    /// [`GossipMessage::arrival_ms`].
    offset_ms: Option<u64>,
    current_time_ms: Option<u64>,
    subnet_id: Option<u64>,
    message: String,
    expected: String,
    reason: Option<String>,
}

impl GossipMessage {
    /// The clock reading, in milliseconds since genesis, the message arrives
    /// at: the format's `meta.current_time_ms + offset_ms`.
    ///
    /// Some of gloas's column vectors carry a per-message `current_time_ms`
    /// instead: the generator (`test/gloas/networking/
    /// test_gossip_data_column_sidecar.py`) writes `compute_time_at_slot_ms`
    /// plus 500 there, the same basis as `meta.current_time_ms`, so it is the
    /// absolute reading.
    fn arrival_ms(&self, base_ms: u64) -> Result<u64, String> {
        match (self.offset_ms, self.current_time_ms) {
            (Some(offset), _) => Ok(base_ms + offset),
            (None, Some(absolute)) => Ok(absolute),
            (None, None) => Err(format!(
                "{}: names neither offset_ms nor current_time_ms",
                self.message
            )),
        }
    }
}

fn parse_root(hex_root: &str) -> Root {
    let stripped = hex_root.strip_prefix("0x").unwrap_or(hex_root);
    let bytes = hex::decode(stripped).expect("the fixture's root is valid hex");
    Root::from_slice(&bytes)
}

fn decode_block(case: &Case, name: &str) -> Result<SignedBeaconBlock, String> {
    SignedBeaconBlock::from_ssz(case.fork, &case.ssz_bytes(name))
        .map_err(|err| format!("decoding {name}: {err:?}"))
}

/// `SignedAggregateAndProof` has no `from_ssz(fork, bytes)` of its own (it
/// carries no state, unlike a block or a state, so nothing else in this crate
/// needed one yet): every fork through deneb shares phase0's shape, and
/// electra and fulu share electra's, exactly the split
/// [`SignedAggregateAndProof`]'s own doc describes for
/// [`SignedBeaconBlock::Fulu`]. Gloas has its own, progressive one.
fn decode_signed_aggregate(case: &Case, name: &str) -> Result<SignedAggregateAndProof, String> {
    let bytes = case.ssz_bytes(name);
    match case.fork {
        ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb => Ok(SignedAggregateAndProof::Phase0(
            phase0::SignedAggregateAndProof::from_ssz_bytes(&bytes)
                .map_err(|err| format!("decoding {name}: {err:?}"))?,
        )),
        ForkName::Electra | ForkName::Fulu => Ok(SignedAggregateAndProof::Electra(
            electra::SignedAggregateAndProof::from_ssz_bytes(&bytes)
                .map_err(|err| format!("decoding {name}: {err:?}"))?,
        )),
        ForkName::Gloas | ForkName::Heze => Ok(SignedAggregateAndProof::Gloas(
            gloas::SignedAggregateAndProof::from_ssz_bytes(&bytes)
                .map_err(|err| format!("decoding {name}: {err:?}"))?,
        )),
        ForkName::Lean => Err(format!("no aggregate shape for fork {:?}", case.fork)),
    }
}

/// [`super::case_config`], plus this suite's own `genesis_time` override.
///
/// The vectors that pin a non-default blob schedule ship a full
/// `config.yaml` alongside their blocks and state, which the compiled-in
/// preset config does not share; [`super::case_config`] is what reads it (or
/// falls back) and corrects `seconds_per_slot`. Gossip validation additionally
/// checks timestamps against the wall clock relative to `state.genesis_time`,
/// which no case's `config.yaml` carries (every one of them was generated
/// under [`super::PRESET`]'s own preset default), so this suite alone
/// overrides it from the decoded state rather than trusting whatever
/// `case_config` returned.
fn case_config(case: &Case, state: &BeaconState) -> Config {
    let mut config = super::case_config(case);
    config.genesis_time = state.genesis_time();
    config
}

/// Delivers `entry`'s execution payload envelope, if it lists one, so
/// `is_payload_verified` answers true for its block.
///
/// `trusted` records the envelope the way the specification's own bid and
/// preferences generators do (`store.payloads[root] = envelope.message`, no
/// verification): their gas-limit cases deliberately give the head an envelope
/// whose payload gas limit differs from the block's bid, which
/// `verify_execution_payload_envelope` would refuse.
fn deliver_payload(
    store: &mut Store,
    case: &Case,
    entry: &StoreBlock,
    config: &Config,
    trusted: bool,
) -> Result<(), String> {
    let Some(name) = &entry.payload else {
        return Ok(());
    };
    let envelope = gloas::SignedExecutionPayloadEnvelope::from_ssz_bytes(&case.ssz_bytes(name))
        .map_err(|err| format!("decoding {name}: {err:?}"))?;
    if trusted {
        fork_choice::accept_execution_payload_envelope(store, &envelope);
        return Ok(());
    }
    // No sampled columns are named, so the empty retrieval reads as available,
    // as in the fork-choice runner's envelope step.
    fork_choice::on_execution_payload_envelope(
        store,
        &envelope,
        config,
        &[],
        &ExecutionEngine::valid(),
    )
    .map_err(|err| format!("delivering {name}: {err:?}"))
}

/// The operation vectors build their anchor pair loosely: the state's
/// `latest_block_header` need not describe the anchor block (different slot,
/// proposer, parent or body), and the block's `state_root` is simply the
/// state's root.
///
/// The specification's `get_forkchoice_store` asserts only
/// `anchor_block.state_root == hash_tree_root(anchor_state)`, which these
/// vectors satisfy. `fork_choice::get_forkchoice_store` runs a different
/// check on purpose (a checkpoint-synced anchor state can be past its block,
/// where the spec's condition fails): it asserts
/// `hash_tree_root(anchor_state.latest_block_header) ==
/// hash_tree_root(anchor_block.message)`, after filling the header's
/// `state_root`. That is looser for a state advanced past its block, but these
/// vectors' stale headers fail it. Rewriting is safe for these four topics
/// because their rules read only the state's slot, validators, fork and
/// `genesis_validators_root`, never its header or the anchor block's contents. So the header is made to name
/// the anchor block with the state root left for the store to fill in, and the
/// block's `state_root` is the root of the state so amended.
fn rebase_stale_header(state: &mut BeaconState, anchor: &mut SignedBeaconBlock) {
    use ethlambda_state_transition::beacon::containers::BeaconBlockHeader;
    use ethlambda_state_transition::beacon::primitives::HashTreeRoot as _;

    let SignedBeaconBlock::Fulu(block) = anchor else {
        return;
    };
    if state.slot() != block.message.slot {
        return;
    }
    let message = &mut block.message;
    *state.latest_block_header_mut() = BeaconBlockHeader {
        slot: message.slot,
        proposer_index: message.proposer_index,
        parent_root: message.parent_root,
        state_root: Root::ZERO,
        body_root: message.body.hash_tree_root(),
    };
    message.state_root = state.hash_tree_root();
}

/// The two topics whose cases share one store setup and one market.
fn is_builder_market_topic(topic: &str) -> bool {
    matches!(topic, "execution_payload_bid" | "proposer_preferences")
}

/// The store the case describes: its anchor, then each listed block.
fn build_store(
    case: &Case,
    meta: &Meta,
    state: BeaconState,
    config: &Config,
) -> Result<Store, String> {
    let (anchor, rest) = meta
        .blocks
        .split_first()
        .ok_or("a gossip case lists at least its anchor block")?;
    let mut anchor_block = decode_block(case, &anchor.block)?;
    let mut state = state;
    if meta.is_operation_topic() {
        if !rest.is_empty() {
            return Err(
                "an operation vector lists blocks after its anchor, which the \
                 rebased anchor could not be their parent"
                    .into(),
            );
        }
        rebase_stale_header(&mut state, &mut anchor_block);
    }
    let backend = Arc::new(ethlambda_storage::backend::InMemoryBackend::new());
    let mut store = fork_choice::get_forkchoice_store(backend, state, anchor_block, config)
        .map_err(|err| format!("get_forkchoice_store: {err:?}"))?;
    let builder_market = is_builder_market_topic(&meta.topic);
    let trusted = builder_market;
    let mut imported = Vec::new();

    // The store's clock at the case's base time, so `on_block` accepts every
    // listed block; a block from a slot past that time advances it to that
    // slot's start, since a vector may place its base time just before the
    // slot a clock-disparity case sends its sidecar for.
    let mut clock_s = (config.genesis_time_ms() + meta.base_ms()?) / 1000;
    fork_choice::on_tick(&mut store, clock_s, config);
    deliver_payload(&mut store, case, anchor, config, trusted)?;

    for entry in rest {
        let block = decode_block(case, &entry.block)?;
        let root = block.message_hash_tree_root();
        let block_slot = block.slot();
        let block_start_s =
            (config.genesis_time_ms() + block.slot() * config.slot_duration_ms) / 1000;
        if block_start_s > clock_s {
            clock_s = block_start_s;
            fork_choice::on_tick(&mut store, clock_s, config);
        }
        // Gloas's `payload_status` is the verdict on the block's envelope, not
        // on the block, which is imported regardless; it feeds the attestation
        // rules' `block_payload_statuses` instead.
        let gloas = case.fork.is_gloas_or_later();
        // Seen without a post-state. A pre-gloas `INVALIDATED` payload lands
        // here too: this store never keeps a post-state for one, since
        // `on_block` fails it and invalidates the branch.
        if entry.failed
            || entry.pending
            || (!gloas && entry.payload_status.as_deref() == Some("INVALIDATED"))
        {
            store
                .insert_pending_block(root, block)
                .map_err(|err| format!("storing {}: {err}", entry.block))?;
            continue;
        }
        let validity = match entry.payload_status.as_deref() {
            _ if gloas => PayloadValidity::NotRequired,
            None => PayloadValidity::NotRequired,
            Some("VALID") => PayloadValidity::Validated,
            Some("NOT_VALIDATED") => PayloadValidity::Optimistic,
            Some(other) => return Err(format!("unknown payload_status {other}")),
        };
        fork_choice::on_block(
            &mut store,
            block,
            config,
            &DataAvailability::NotRequired,
            &validity,
            &CommitteeCache::default(),
        )
        .map_err(|err| format!("importing {}: {err:?}", entry.block))?;
        deliver_payload(&mut store, case, entry, config, trusted)?;
        imported.push(root);
        if gloas && let Some(status) = entry.payload_status.as_deref() {
            let status = match status {
                "VALID" => PayloadStatusEnum::Valid,
                "NOT_VALIDATED" => PayloadStatusEnum::Syncing,
                "INVALIDATED" => PayloadStatusEnum::Invalid,
                other => return Err(format!("unknown payload_status {other}")),
            };
            store.insert_beacon_block_payload_status(root, block_slot, status);
        }
    }

    // The inclusion list rules read it too, through `is_valid_dependent_root`.
    if builder_market || meta.topic == "inclusion_list" {
        // `on_block` records no head, and the bid and preference rules read
        // the recorded one. Computed before the finalized override below:
        // raising finality prunes the live chain below the finalized block,
        // which takes the anchor (still the store's justified root) out of
        // the index `get_head` starts its walk from. The specification's
        // store never prunes, so its `get_head` starts from the anchor too,
        // and every listed block descends from the finalized one, so the
        // head is the same either way.
        fork_choice::get_head(&mut store, config)
            .map_err(|err| format!("computing the head: {err:?}"))?;
    }

    if let Some(finalized) = &meta.finalized_checkpoint {
        let root = match (&finalized.root, &finalized.block) {
            (Some(hex), None) => parse_root(hex),
            (None, Some(name)) => decode_block(case, name)?.message_hash_tree_root(),
            _ => return Err("finalized_checkpoint names exactly one of root and block".into()),
        };
        let checkpoint = Store::beacon_checkpoint_as_stored(Checkpoint {
            epoch: finalized.epoch,
            root,
        });
        let head = store
            .head()
            .map_err(|err| format!("reading the head: {err}"))?;
        store
            .update_checkpoints(ForkCheckpoints::new(head, None, Some(checkpoint)))
            .map_err(|err| format!("overriding the finalized checkpoint: {err}"))?;
        if builder_market {
            // The bid generators activate their builders by finalizing epoch 1
            // in the store *and* in the head's post-state (a replayed chain of
            // empty blocks never finalizes), and say so through this override.
            for block_root in &imported {
                let Some(state) = store
                    .get_state(block_root)
                    .map_err(|err| format!("reading a state: {err}"))?
                else {
                    continue;
                };
                let mut state = (*state).clone();
                *state.finalized_checkpoint_mut() = Checkpoint {
                    epoch: finalized.epoch,
                    root,
                };
                store
                    .insert_state(*block_root, state)
                    .map_err(|err| format!("overriding a state's finalized checkpoint: {err}"))?;
            }
        }
    }

    Ok(store)
}

/// `valid` is Accept, `reject` is Reject, `ignore` is Ignore or Queue (both
/// are IGNORE to gossipsub).
fn check(message: &GossipMessage, outcome: Outcome) -> Result<(), String> {
    let matches = match message.expected.as_str() {
        "valid" => outcome == Outcome::Accept,
        "ignore" => matches!(outcome, Outcome::Ignore(_) | Outcome::Queue(_)),
        "reject" => matches!(outcome, Outcome::Reject(_)),
        other => return Err(format!("unknown expected result {other}")),
    };
    if matches {
        return Ok(());
    }
    Err(format!(
        "{}: expected {} ({}), got {outcome:?}",
        message.message,
        message.expected,
        message.reason.as_deref().unwrap_or("no reason given"),
    ))
}

/// The four operation topics share one verdict-then-record shape.
fn validate_operation(
    seen: &mut SeenOperations,
    store: &Store,
    operation: BeaconOperation,
    now_ms: u64,
) -> Outcome {
    let outcome = rules::operations::validate(seen, store, &operation, now_ms);
    if outcome == Outcome::Accept {
        seen.record(&operation);
    }
    outcome
}

fn run_case(case: &Case) -> Result<(), String> {
    let meta: Meta = case.yaml("meta");
    let state = BeaconState::from_ssz(case.fork, &case.ssz_bytes("state"))
        .map_err(|err| format!("decoding state: {err:?}"))?;
    let config = case_config(case, &state);
    let store = build_store(case, &meta, state, &config)?;
    let market = BuilderMarket::default();
    let capacity = NonZeroUsize::new(SEEN_CAPACITY).expect("non-zero");
    let mut seen_blocks = SeenBlocks::new(capacity);
    let mut seen_columns = SeenColumns::new(capacity);
    let mut seen_block_columns = SeenBlockColumns::new(capacity);
    let mut seen_aggregates = SeenAggregates::new(capacity, capacity);
    let mut seen_attestations = SeenAttestations::new(capacity);
    let mut seen_envelopes = SeenEnvelopes::new(capacity);
    let mut seen_payload_attestations = SeenPayloadAttestations::new(capacity);
    let mut seen_inclusion_lists = SeenInclusionLists::new(capacity);
    let mut seen_operations = SeenOperations::default();
    let mut seen_sync_messages = SeenSyncCommitteeMessages::new(capacity);
    let mut seen_sync_contributions = SeenSyncContributions::new(capacity, capacity);

    for (index, message) in meta.messages.iter().enumerate() {
        let now_ms = config.genesis_time_ms()
            + meta
                .arrival_ms(message)
                .map_err(|err| format!("message {index}: {err}"))?;
        let outcome = match meta.topic.as_str() {
            "beacon_block" => {
                let block = decode_block(case, &message.message)?;
                let outcome = rules::block::validate(&seen_blocks, &store, &block, now_ms);
                if outcome == Outcome::Accept {
                    let root = block.message_hash_tree_root();
                    seen_blocks.record(block.slot(), block.proposer_index(), root);
                }
                outcome
            }
            "data_column_sidecar" => {
                let sidecar =
                    DataColumnSidecar::from_ssz(case.fork, &case.ssz_bytes(&message.message))
                        .map_err(|err| format!("decoding {}: {err:?}", message.message))?;
                let subnet_id = message
                    .subnet_id
                    .ok_or("a data_column_sidecar message names its subnet")?;
                match sidecar {
                    DataColumnSidecar::Fulu(sidecar) => {
                        let outcome = rules::column::validate(
                            &seen_columns,
                            &store,
                            &sidecar,
                            subnet_id,
                            now_ms,
                        );
                        if outcome == Outcome::Accept {
                            let header = &sidecar.signed_block_header.message;
                            seen_columns.record(header.slot, header.proposer_index, sidecar.index);
                        }
                        outcome
                    }
                    DataColumnSidecar::Gloas(sidecar) => {
                        let outcome = rules::column::validate_gloas(
                            &seen_block_columns,
                            &store,
                            &sidecar,
                            subnet_id,
                            now_ms,
                        );
                        if outcome == Outcome::Accept {
                            seen_block_columns.record(sidecar.beacon_block_root, sidecar.index);
                        }
                        outcome
                    }
                }
            }
            "beacon_aggregate_and_proof" => {
                let aggregate = decode_signed_aggregate(case, &message.message)?;
                let outcome = match rules::aggregate::validate(
                    &seen_aggregates,
                    &store,
                    &aggregate,
                    now_ms,
                ) {
                    Ok(_) => Outcome::Accept,
                    Err(outcome) => outcome,
                };
                if outcome == Outcome::Accept {
                    seen_aggregates.record(&aggregate);
                }
                outcome
            }
            "beacon_attestation" => {
                let attestation =
                    electra::SingleAttestation::from_ssz_bytes(&case.ssz_bytes(&message.message))
                        .map_err(|err| format!("decoding {}: {err:?}", message.message))?;
                let subnet_id = message
                    .subnet_id
                    .ok_or("a beacon_attestation message names its subnet")?;
                let outcome = rules::attestation::validate(
                    &seen_attestations,
                    &store,
                    &attestation,
                    subnet_id,
                    now_ms,
                );
                if outcome == Outcome::Accept {
                    seen_attestations.record(&attestation);
                }
                outcome
            }
            "execution_payload" => {
                let envelope = gloas::SignedExecutionPayloadEnvelope::from_ssz_bytes(
                    &case.ssz_bytes(&message.message),
                )
                .map_err(|err| format!("decoding {}: {err:?}", message.message))?;
                let outcome = rules::envelope::validate(&seen_envelopes, &store, &envelope);
                if outcome == Outcome::Accept {
                    seen_envelopes.record(
                        envelope.message.beacon_block_root,
                        envelope.message.builder_index,
                    );
                }
                outcome
            }
            "payload_attestation_message" => {
                let attestation = gloas::PayloadAttestationMessage::from_ssz_bytes(
                    &case.ssz_bytes(&message.message),
                )
                .map_err(|err| format!("decoding {}: {err:?}", message.message))?;
                let outcome = rules::payload_attestation::validate(
                    &seen_payload_attestations,
                    &store,
                    &attestation,
                    now_ms,
                );
                if outcome == Outcome::Accept {
                    seen_payload_attestations
                        .record(attestation.data.slot, attestation.validator_index);
                }
                outcome
            }
            "voluntary_exit" => {
                let bytes = case.ssz_bytes(&message.message);
                let exit = shared::SignedVoluntaryExit::from_ssz_bytes(&bytes)
                    .map_err(|err| format!("decoding {}: {err:?}", message.message))?;
                validate_operation(
                    &mut seen_operations,
                    &store,
                    BeaconOperation::VoluntaryExit(exit),
                    now_ms,
                )
            }
            "proposer_slashing" => {
                let bytes = case.ssz_bytes(&message.message);
                let slashing = shared::ProposerSlashing::from_ssz_bytes(&bytes)
                    .map_err(|err| format!("decoding {}: {err:?}", message.message))?;
                validate_operation(
                    &mut seen_operations,
                    &store,
                    BeaconOperation::ProposerSlashing(slashing),
                    now_ms,
                )
            }
            "attester_slashing" => {
                let bytes = case.ssz_bytes(&message.message);
                let slashing = electra::AttesterSlashing::from_ssz_bytes(&bytes)
                    .map_err(|err| format!("decoding {}: {err:?}", message.message))?;
                validate_operation(
                    &mut seen_operations,
                    &store,
                    BeaconOperation::AttesterSlashing(slashing),
                    now_ms,
                )
            }
            "bls_to_execution_change" => {
                let bytes = case.ssz_bytes(&message.message);
                let change = capella::SignedBLSToExecutionChange::from_ssz_bytes(&bytes)
                    .map_err(|err| format!("decoding {}: {err:?}", message.message))?;
                validate_operation(
                    &mut seen_operations,
                    &store,
                    BeaconOperation::BlsToExecutionChange(change),
                    now_ms,
                )
            }
            "sync_committee" => {
                let sync_message =
                    altair::SyncCommitteeMessage::from_ssz_bytes(&case.ssz_bytes(&message.message))
                        .map_err(|err| format!("decoding {}: {err:?}", message.message))?;
                let subnet_id = message
                    .subnet_id
                    .ok_or("a sync_committee message names its subnet")?;
                let outcome = match rules::sync_committee::validate_message(
                    &seen_sync_messages,
                    &store,
                    &sync_message,
                    subnet_id,
                    now_ms,
                ) {
                    Ok(_) => Outcome::Accept,
                    Err(outcome) => outcome,
                };
                if outcome == Outcome::Accept {
                    seen_sync_messages.record(
                        sync_message.slot,
                        sync_message.validator_index,
                        subnet_id,
                    );
                }
                outcome
            }
            "sync_committee_contribution_and_proof" => {
                let signed = altair::SignedContributionAndProof::from_ssz_bytes(
                    &case.ssz_bytes(&message.message),
                )
                .map_err(|err| format!("decoding {}: {err:?}", message.message))?;
                let outcome = rules::sync_committee::validate_contribution(
                    &seen_sync_contributions,
                    &store,
                    &signed,
                    now_ms,
                );
                if outcome == Outcome::Accept {
                    seen_sync_contributions.record(&signed);
                }
                outcome
            }
            // The bid cases mix three message types under one topic (the
            // preferences and envelope a bid depends on arrive in order, and
            // share the case's seen state), so the message's own name says
            // which rule judges it.
            "inclusion_list" => run_inclusion_list_message(
                case,
                &store,
                &mut seen_inclusion_lists,
                message,
                now_ms,
                &config,
            )?,
            "execution_payload_bid" | "proposer_preferences" => run_builder_market_message(
                case,
                &store,
                &market,
                &mut seen_envelopes,
                &mut seen_inclusion_lists,
                message,
                now_ms,
                &config,
            )?,
            other => return Err(format!("topic {other} has no runner")),
        };
        check(message, outcome).map_err(|err| format!("message {index}: {err}"))?;
    }
    Ok(())
}

/// One `inclusion_list` message: the gossip rules, then, on `Accept`, the
/// seen count and the inclusion list store the p2p handler records it in.
fn run_inclusion_list_message(
    case: &Case,
    store: &Store,
    seen: &mut SeenInclusionLists,
    message: &GossipMessage,
    now_ms: u64,
    config: &Config,
) -> Result<Outcome, String> {
    let signed = heze::SignedInclusionList::from_ssz_bytes(&case.ssz_bytes(&message.message))
        .map_err(|err| format!("decoding {}: {err:?}", message.message))?;
    let outcome = rules::inclusion_list::validate(seen, store, &signed, now_ms);
    if outcome == Outcome::Accept {
        seen.record(&signed);
        let timely = is_inclusion_list_timely(config, signed.message.slot, now_ms);
        store
            .inclusion_list_store()
            .process_inclusion_list(signed, timely);
    }
    Ok(outcome)
}

/// One message of a `execution_payload_bid` or `proposer_preferences` case.
/// A heze bid case also carries the inclusion list its bid's bits are judged
/// against.
#[allow(clippy::too_many_arguments)]
fn run_builder_market_message(
    case: &Case,
    store: &Store,
    market: &BuilderMarket,
    seen_envelopes: &mut SeenEnvelopes,
    seen_inclusion_lists: &mut SeenInclusionLists,
    message: &GossipMessage,
    now_ms: u64,
    config: &Config,
) -> Result<Outcome, String> {
    let bytes = case.ssz_bytes(&message.message);
    let decode_err = |err| format!("decoding {}: {err:?}", message.message);
    if message.message.starts_with("proposer_preferences_") {
        let preferences =
            gloas::SignedProposerPreferences::from_ssz_bytes(&bytes).map_err(decode_err)?;
        let outcome = rules::proposer_preferences::validate(market, store, &preferences, now_ms);
        if outcome == Outcome::Accept {
            let wall_slot =
                now_ms.saturating_sub(config.genesis_time_ms()) / config.slot_duration_ms;
            market.record_preferences(preferences, wall_slot);
        }
        Ok(outcome)
    } else if message.message.starts_with("execution_payload_envelope_") {
        let envelope =
            gloas::SignedExecutionPayloadEnvelope::from_ssz_bytes(&bytes).map_err(decode_err)?;
        let outcome = rules::envelope::validate(seen_envelopes, store, &envelope);
        if outcome == Outcome::Accept {
            seen_envelopes.record(
                envelope.message.beacon_block_root,
                envelope.message.builder_index,
            );
            market.record_execution_payload(&envelope.message);
        }
        Ok(outcome)
    } else if message.message.starts_with("inclusion_list_") {
        run_inclusion_list_message(case, store, seen_inclusion_lists, message, now_ms, config)
    } else if message.message.starts_with("execution_payload_bid_") {
        let bid = gloas::SignedExecutionPayloadBid::from_ssz_bytes(&bytes).map_err(decode_err)?;
        let outcome = rules::execution_payload_bid::validate(market, store, &bid, now_ms);
        if outcome == Outcome::Accept {
            market.record_bid(bid);
        }
        Ok(outcome)
    } else {
        Err(format!("{} is of no known message type", message.message))
    }
}

pub fn trials() -> Vec<Trial> {
    let mut trials = Vec::new();
    for handler in HANDLERS {
        let cases = collect(PRESET, "networking", handler);
        trials.push(super::discovery_trial(
            &format!("gossip/{handler}"),
            cases.len(),
        ));
        for case in cases {
            // A fork the handler's rules do not cover is ignored rather than
            // run; see [`validated_forks`].
            let ignored = !case.in_scope()
                || !validated_forks(handler).contains(&case.fork)
                || SKIPPED.iter().any(|(name, _)| *name == case.name);
            trials.push(super::case_trial("gossip", case, run_case).with_ignored_flag(ignored));
        }
    }

    // Every other `gossip_*` handler and fork this fixture tree ships: named
    // and ignored rather than left for the loop above to never mention, and
    // `unknown` is what makes a fixture release adding a handler neither run
    // nor listed here fail loudly instead of vanishing. Mirrors
    // `fixture_fork_trials`'s treatment of `UNMODELED_FORKS`.
    let mut unknown: BTreeSet<String> = BTreeSet::new();
    for (handler, case) in collect_all_handlers(PRESET, "networking") {
        if !handler.starts_with("gossip_") || HANDLERS.contains(&handler.as_str()) {
            continue;
        }
        if !IGNORED_HANDLERS.contains(&handler.as_str()) {
            unknown.insert(handler);
            continue;
        }
        let name = format!("gossip/{}", case.id());
        trials.push(Trial::test(name, || Ok(())).with_ignored_flag(true));
    }

    trials.push(Trial::test(
        "gossip/every_handler_is_accounted_for",
        move || {
            if unknown.is_empty() {
                return Ok(());
            }
            Err(Failed::from(format!(
                "the fixture release ships gossip_* handlers this runner neither runs nor lists \
                 in IGNORED_HANDLERS, so every case under them is skipped without appearing \
                 anywhere in the output: {}",
                unknown.into_iter().collect::<Vec<_>>().join(", ")
            )))
        },
    ));

    trials
}
