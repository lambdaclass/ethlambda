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
use ethlambda_state_transition::beacon::config::Config;
use ethlambda_state_transition::beacon::containers::{
    BeaconState, Checkpoint, DataColumnSidecar, SignedAggregateAndProof, SignedBeaconBlock,
    electra, phase0,
};
use ethlambda_state_transition::beacon::fork_choice::{
    self, DataAvailability, PayloadValidity, Store,
};
use ethlambda_state_transition::beacon::gossip::{
    self as rules, Outcome, SeenAggregates, SeenAttestations, SeenBlockColumns, SeenBlocks,
    SeenColumns,
};
use ethlambda_state_transition::beacon::helpers::accessors::CommitteeCache;
use ethlambda_state_transition::beacon::primitives::Root;
use ethlambda_storage::ForkCheckpoints;
use libssz::SszDecode;
use libtest_mimic::{Failed, Trial};

use super::{Case, PRESET, collect, collect_all_handlers};

/// The handlers this runner covers, and runs.
const HANDLERS: &[&str] = &[
    "gossip_beacon_block",
    "gossip_data_column_sidecar",
    "gossip_beacon_aggregate_and_proof",
    "gossip_beacon_attestation",
];

/// The forks each of [`HANDLERS`] validates. A case from any other fork is
/// reported as ignored rather than run, the same "known gap, not a silent one"
/// treatment `case.in_scope()` gives a fork past `HIGHEST_IMPLEMENTED_FORK`.
///
/// `case.in_scope()` alone would pass every fork up to gloas, since the state
/// transition handles them all; the gossip rules do not. The block rules
/// (`beacon::gossip::block`) are fulu's `validate_beacon_block_gossip`, and the
/// aggregate and attestation rules (`beacon::gossip::{aggregate, attestation}`)
/// are electra's, which fulu keeps. The column rules have both fulu's and
/// gloas's (`beacon::gossip::column`).
fn validated_forks(handler: &str) -> &'static [ForkName] {
    match handler {
        "gossip_data_column_sidecar" => &[ForkName::Fulu, ForkName::Gloas],
        "gossip_beacon_block"
        | "gossip_beacon_aggregate_and_proof"
        | "gossip_beacon_attestation" => &[ForkName::Fulu],
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
/// `gossip_execution_payload_bid`, `gossip_execution_payload_envelope`,
/// `gossip_payload_attestation_message`, and `gossip_proposer_preferences`
/// are gloas's own topics (EIP-7732 ePBS): the builder's bid, the revealed
/// payload envelope, the payload timeliness committee's vote, and a
/// builder's advertised preferences, respectively. None of them existed
/// until gloas's fixture directory started parsing (`ForkName::Gloas`), so
/// they land here rather than silently in `unknown` the first time this
/// runner sees them. Alphabetized with the rest rather than kept together.
const IGNORED_HANDLERS: &[&str] = &[
    "gossip_attester_slashing",
    "gossip_blob_sidecar",
    "gossip_bls_to_execution_change",
    "gossip_execution_payload_bid",
    "gossip_execution_payload_envelope",
    "gossip_partial_data_column_sidecar",
    "gossip_payload_attestation_message",
    "gossip_proposer_preferences",
    "gossip_proposer_slashing",
    "gossip_sync_committee_contribution_and_proof",
    "gossip_sync_committee_message",
    "gossip_voluntary_exit",
];

/// Vectors that disagree with a deliberate deviation, by case name.
const SKIPPED: &[(&str, &str)] = &[
    (
        "gossip_beacon_block__reject_parent_consensus_failed_execution_not_verified",
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
];

/// Capacity for a case's seen caches. A case sends a handful of messages.
const SEEN_CAPACITY: usize = 64;

#[derive(serde::Deserialize)]
struct Meta {
    topic: String,
    #[serde(default)]
    blocks: Vec<StoreBlock>,
    finalized_checkpoint: Option<FinalizedOverride>,
    current_time_ms: u64,
    messages: Vec<GossipMessage>,
}

#[derive(serde::Deserialize)]
struct StoreBlock {
    block: String,
    #[serde(default)]
    failed: bool,
    #[serde(default)]
    pending: bool,
    payload_status: Option<String>,
}

#[derive(serde::Deserialize)]
struct FinalizedOverride {
    epoch: u64,
    root: Option<String>,
    block: Option<String>,
}

#[derive(serde::Deserialize)]
struct GossipMessage {
    /// Missing from gloas's column vectors, which name the message's clock
    /// reading in `current_time_ms` instead; see [`GossipMessage::arrival_ms`].
    offset_ms: Option<u64>,
    current_time_ms: Option<u64>,
    subnet_id: Option<u64>,
    message: String,
    expected: String,
    reason: Option<String>,
}

impl GossipMessage {
    /// The clock reading, in milliseconds since genesis, the message arrives
    /// at: the format's `meta.current_time_ms + offset_ms`. Gloas's column
    /// vectors instead carry a per-message `current_time_ms`, which is read as
    /// the absolute reading (every such vector states a time later than the
    /// meta's own base and inside the slot its sidecar is for).
    fn arrival_ms(&self, base_ms: u64) -> u64 {
        match (self.offset_ms, self.current_time_ms) {
            (Some(offset), _) => base_ms + offset,
            (None, Some(absolute)) => absolute,
            (None, None) => base_ms,
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
/// [`SignedBeaconBlock::Fulu`]. Gloas's own aggregate has no modeled variant,
/// and this runner does not run its cases (see [`trials`]), so it is refused
/// by name.
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
        ForkName::Gloas | ForkName::Lean => {
            Err(format!("no aggregate shape for fork {:?}", case.fork))
        }
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
    let anchor_block = decode_block(case, &anchor.block)?;
    let backend = Arc::new(ethlambda_storage::backend::InMemoryBackend::new());
    let mut store = fork_choice::get_forkchoice_store(backend, state, anchor_block, config)
        .map_err(|err| format!("get_forkchoice_store: {err:?}"))?;

    // The store's clock at the case's base time, so `on_block` accepts every
    // listed block; a block from a slot past that time advances it to that
    // slot's start, since a vector may place its base time just before the
    // slot a clock-disparity case sends its sidecar for.
    let mut clock_s = (config.genesis_time_ms() + meta.current_time_ms) / 1000;
    fork_choice::on_tick(&mut store, clock_s, config);

    for entry in rest {
        let block = decode_block(case, &entry.block)?;
        let root = block.message_hash_tree_root();
        let block_start_s =
            (config.genesis_time_ms() + block.slot() * config.slot_duration_ms) / 1000;
        if block_start_s > clock_s {
            clock_s = block_start_s;
            fork_choice::on_tick(&mut store, clock_s, config);
        }
        // Seen without a post-state. An `INVALIDATED` payload lands here too:
        // this store never keeps a post-state for one, since `on_block` fails
        // it and invalidates the branch.
        if entry.failed || entry.pending || entry.payload_status.as_deref() == Some("INVALIDATED") {
            store
                .insert_pending_block(root, block)
                .map_err(|err| format!("storing {}: {err}", entry.block))?;
            continue;
        }
        let validity = match entry.payload_status.as_deref() {
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

fn run_case(case: &Case) -> Result<(), String> {
    let meta: Meta = case.yaml("meta");
    let state = BeaconState::from_ssz(case.fork, &case.ssz_bytes("state"))
        .map_err(|err| format!("decoding state: {err:?}"))?;
    let config = case_config(case, &state);
    let store = build_store(case, &meta, state, &config)?;
    let capacity = NonZeroUsize::new(SEEN_CAPACITY).expect("non-zero");
    let mut seen_blocks = SeenBlocks::new(capacity);
    let mut seen_columns = SeenColumns::new(capacity);
    let mut seen_block_columns = SeenBlockColumns::new(capacity);
    let mut seen_aggregates = SeenAggregates::new(capacity, capacity);
    let mut seen_attestations = SeenAttestations::new(capacity);

    for (index, message) in meta.messages.iter().enumerate() {
        let now_ms = config.genesis_time_ms() + message.arrival_ms(meta.current_time_ms);
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
            other => return Err(format!("topic {other} has no runner")),
        };
        check(message, outcome).map_err(|err| format!("message {index}: {err}"))?;
    }
    Ok(())
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
