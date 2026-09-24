//! The `networking/gossip_*` runners: the specification's gossip validation
//! vectors (`tests/formats/networking/gossip_validation.md` in
//! consensus-specs), run against `beacon::gossip`.
//!
//! These come from their own fixture tree; see [`super::gossip_fixture_root`].

use std::num::NonZeroUsize;
use std::sync::Arc;

use ethlambda_state_transition::beacon::ForkName;
use ethlambda_state_transition::beacon::config::Config;
use ethlambda_state_transition::beacon::containers::{
    BeaconState, Checkpoint, SignedBeaconBlock, fulu,
};
use ethlambda_state_transition::beacon::fork_choice::{
    self, DataAvailability, PayloadValidity, Store,
};
use ethlambda_state_transition::beacon::gossip::{self as rules, Outcome, SeenBlocks, SeenColumns};
use ethlambda_state_transition::beacon::helpers::accessors::CommitteeCache;
use ethlambda_state_transition::beacon::primitives::Root;
use ethlambda_storage::ForkCheckpoints;
use libssz::SszDecode;
use libtest_mimic::Trial;

use super::{Case, PRESET, collect_gossip};

/// The handlers this runner covers.
const HANDLERS: &[&str] = &["gossip_beacon_block", "gossip_data_column_sidecar"];

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
    offset_ms: u64,
    subnet_id: Option<u64>,
    message: String,
    expected: String,
    reason: Option<String>,
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

/// The case's own `config.yaml`, when it carries one: the vectors that pin a
/// non-default blob schedule ship a full config alongside their blocks and
/// state, which the compiled-in preset config does not share.
///
/// Most cases carry no `config.yaml` at all. Per the consensus-specs tests
/// format README, a present `config.yaml` replaces the default runtime
/// config, and an absent one means the preset default; the README says
/// nothing about what fork epochs a present one holds. That is instead an
/// observation of the vectors' own `config.yaml` files (checked by hand):
/// every one of them sets every fork epoch to zero. So the fallback here
/// models that same all-forks-at-genesis shape by hand: the compiled preset
/// with every fork from altair up to and including the case's own fork pulled
/// back to genesis, which is enough for `Config::fork_at_epoch` to resolve
/// every case's low-epoch state without leaving a later fork's tree to
/// inherit an earlier fork's fallback.
fn case_config(case: &Case, state: &BeaconState) -> Config {
    let mut config: Config = case.yaml_opt("config").unwrap_or_else(|| {
        ForkName::ALL
            .into_iter()
            .take_while(|fork| *fork <= case.fork)
            .filter(|fork| *fork != ForkName::Phase0)
            .fold(Config::active(), |config, fork| {
                config.with_fork_epoch(fork, 0)
            })
    });
    config.genesis_time = state.genesis_time();
    // Newer configs name only `SLOT_DURATION_MS`; without `SECONDS_PER_SLOT`
    // the field would keep mainnet's default.
    config.seconds_per_slot = config.slot_duration_ms / 1000;
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
    // listed block.
    let now_s = (config.genesis_time_ms() + meta.current_time_ms) / 1000;
    fork_choice::on_tick(&mut store, now_s, config);

    for entry in rest {
        let block = decode_block(case, &entry.block)?;
        let root = block.message_hash_tree_root();
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
            &mut CommitteeCache::default(),
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

    for (index, message) in meta.messages.iter().enumerate() {
        let now_ms = config.genesis_time_ms() + meta.current_time_ms + message.offset_ms;
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
                    fulu::DataColumnSidecar::from_ssz_bytes(&case.ssz_bytes(&message.message))
                        .map_err(|err| format!("decoding {}: {err:?}", message.message))?;
                let subnet_id = message
                    .subnet_id
                    .ok_or("a data_column_sidecar message names its subnet")?;
                let outcome =
                    rules::column::validate(&seen_columns, &store, &sidecar, subnet_id, now_ms);
                if outcome == Outcome::Accept {
                    let header = &sidecar.signed_block_header.message;
                    seen_columns.record(header.slot, header.proposer_index, sidecar.index);
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
        let cases = collect_gossip(PRESET, handler);
        trials.push(super::discovery_trial(
            &format!("gossip/{handler}"),
            cases.len(),
        ));
        for case in cases {
            let ignored = !case.in_scope() || SKIPPED.iter().any(|(name, _)| *name == case.name);
            trials.push(super::case_trial("gossip", case, run_case).with_ignored_flag(ignored));
        }
    }
    trials
}
