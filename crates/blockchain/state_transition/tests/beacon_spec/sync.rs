//! The `sync` runner: optimistic sync.
//!
//! The fixture format is the `fork_choice` runner's, plus one step kind. An
//! `on_payload_info` step seeds the status a mock execution client returns for
//! one payload, keyed by that payload's execution block hash; a later `block`
//! step then imports a block whose payload has that hash, and the seeded status
//! is what [`fork_choice::on_block`] is given.
//!
//! Only the steps this suite's released cases actually use are handled. There
//! is exactly one case, `from_syncing_to_invalid`, at every fork from bellatrix
//! on and in both presets, and it uses `tick`, `on_payload_info`, `block` and
//! `checks`. A step kind outside that set fails loudly rather than being
//! skipped: a suite that silently ignores what it does not understand reports
//! coverage it does not have.
//!
//! # Why this is not a flag on the `fork_choice` runner
//!
//! The two runners answer to different fixture directories and different step
//! vocabularies, and `fork_choice`'s cases must keep getting
//! [`PayloadValidity::NotRequired`] for every block: no released `fork_choice`
//! case carries an `on_payload_info` step, so any that suddenly consulted a
//! registry would be reading state no fixture set.
//!
//! # The one place a rejected block still changes the store
//!
//! Everywhere else in this test suite, a step expecting `valid: false` can
//! stop there, because a rejected handler call leaves the store as it found
//! it. An `INVALIDATED` payload is the exception the specification writes in:
//! the case's last step rejects a block *and* requires the branch under its
//! condemned ancestor to have left fork choice, which is why the head it then
//! checks is chain a's tip rather than chain b's.

use std::sync::Arc;

use ethlambda_state_transition::beacon::config::Config;
use ethlambda_state_transition::beacon::containers::{BeaconState, SignedBeaconBlock};
use ethlambda_state_transition::beacon::fork_choice::{
    self, PayloadStatusEnum, PayloadStatusV1, PayloadValidity, Store,
};
use ethlambda_state_transition::beacon::helpers::accessors::CommitteeCache;
use ethlambda_state_transition::beacon::primitives::ExecutionBlockHash;
use libtest_mimic::Trial;

use super::{Case, PRESET, collect_all_handlers};

/// One entry of a case's `steps.yaml`.
///
/// The same overlay-of-optional-fields shape the `fork_choice` runner's own
/// `Step` uses, narrowed to the kinds this suite's cases carry and widened by
/// [`Step::block_hash`]/[`Step::payload_status`].
#[derive(serde::Deserialize)]
struct Step {
    /// The Unix-second time to advance the store to, for an `on_tick` step.
    tick: Option<u64>,
    /// The `block_<root>` file naming the block for an `on_block` step.
    block: Option<String>,
    /// An `on_payload_info` step's payload, identified by its execution block
    /// hash. Always paired with [`Step::payload_status`].
    block_hash: Option<String>,
    /// The status the mock execution client is to return for
    /// [`Step::block_hash`]'s payload.
    payload_status: Option<StepPayloadStatus>,
    /// Whether this step's call is expected to succeed.
    #[serde(default = "default_valid")]
    valid: bool,
    /// The assertions to check against the current store.
    checks: Option<super::fork_choice::Checks>,
}

/// [`Step::valid`]'s default: a step not naming its own validity is expected
/// to succeed.
fn default_valid() -> bool {
    true
}

/// The `payload_status` object of an `on_payload_info` step.
#[derive(serde::Deserialize)]
struct StepPayloadStatus {
    status: String,
    latest_valid_hash: Option<String>,
    validation_error: Option<String>,
}

/// Parses a fixture's `0x`-prefixed hex execution block hash.
fn parse_execution_block_hash(value: &str) -> Result<ExecutionBlockHash, String> {
    let stripped = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(stripped).map_err(|err| format!("decoding {value}: {err}"))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{value} is not 32 bytes"))?;
    Ok(ExecutionBlockHash::from(array))
}

/// Reads one of the format's status strings.
fn parse_status(name: &str) -> Result<PayloadStatusEnum, String> {
    match name {
        "VALID" => Ok(PayloadStatusEnum::Valid),
        "INVALID" => Ok(PayloadStatusEnum::Invalid),
        "SYNCING" => Ok(PayloadStatusEnum::Syncing),
        "ACCEPTED" => Ok(PayloadStatusEnum::Accepted),
        "INVALID_BLOCK_HASH" => Ok(PayloadStatusEnum::InvalidBlockHash),
        other => Err(format!("unknown payload status {other}")),
    }
}

/// The verdict [`fork_choice::on_block`] gets for this block: whatever an
/// `on_payload_info` step seeded for its own payload's hash.
///
/// An unseeded payload answers [`PayloadValidity::NotRequired`], which is both
/// what the format implies (its note requires a status to be initialized
/// *before* the corresponding `on_block` step) and what keeps a pre-bellatrix
/// block, which has no payload to seed a status for, behaving as it always did.
///
/// Goes through [`fork_choice::payload_validity`] rather than matching on the
/// status here, so this suite proves the production reading of
/// `optimistic-sync.md`'s two aliases rather than a copy of it living in a
/// test.
fn seeded_validity(store: &Store, block: &SignedBeaconBlock) -> PayloadValidity {
    let Some(el_hash) = block.execution_block_hash() else {
        return PayloadValidity::NotRequired;
    };
    match store.beacon_payload_status(el_hash) {
        Some(status) => fork_choice::payload_validity(&status),
        None => PayloadValidity::NotRequired,
    }
}

/// Applies one non-`checks` step, dispatching on which of [`Step::tick`],
/// [`Step::block_hash`] or [`Step::block`] is set.
fn apply_step(store: &mut Store, case: &Case, step: &Step, config: &Config) -> Result<(), String> {
    if let Some(time) = step.tick {
        fork_choice::on_tick(store, time, config);
        return Ok(());
    }

    if let (Some(block_hash), Some(status)) = (&step.block_hash, &step.payload_status) {
        let block_hash = parse_execution_block_hash(block_hash)?;
        let latest_valid_hash = match &status.latest_valid_hash {
            Some(value) => Some(parse_execution_block_hash(value)?),
            None => None,
        };
        store.insert_beacon_payload_status(
            block_hash,
            PayloadStatusV1 {
                status: parse_status(&status.status)?,
                latest_valid_hash,
                validation_error: status.validation_error.clone(),
            },
        );
        return Ok(());
    }

    if let Some(name) = &step.block {
        return apply_block(store, case, name, step.valid, config);
    }

    Err("a step carried no kind this runner handles".to_string())
}

/// Decodes a `block` step's block, reads the verdict an earlier
/// `on_payload_info` step seeded for it, calls [`fork_choice::on_block`], and,
/// only if the block was accepted, replays every attestation and attester
/// slashing carried in its body.
///
/// The replay is what makes this case's head move: chain b's blocks carry the
/// attestations that give it more weight than chain a, so without it the
/// invalidation at the end would have nothing to take back.
fn apply_block(
    store: &mut Store,
    case: &Case,
    name: &str,
    expect_valid: bool,
    config: &Config,
) -> Result<(), String> {
    let signed_block = super::fork_choice::decode_signed_block(case, name)?;
    let validity = seeded_validity(store, &signed_block);
    // Collected before `on_block` moves `signed_block` in, so they are still
    // available for the replay below after a successful call.
    let (attestations, attester_slashings) = fork_choice::block_operations(&signed_block);

    match (
        fork_choice::on_block(
            store,
            signed_block,
            config,
            &fork_choice::DataAvailability::NotRequired,
            &validity,
            &mut CommitteeCache::default(),
        ),
        expect_valid,
    ) {
        (Ok(()), false) => {
            return Err(format!(
                "{name} was accepted, but the step expects it to be rejected"
            ));
        }
        (Err(err), true) => return Err(format!("{name} was rejected: {err:?}")),
        // Correctly rejected. Unlike every other runner's equivalent arm, the
        // store is not necessarily untouched: see the module documentation.
        (Err(_), false) => return Ok(()),
        (Ok(()), true) => {}
    }

    for attestation in &attestations {
        fork_choice::on_attestation(
            store,
            attestation,
            true,
            config,
            &mut CommitteeCache::default(),
        )
        .map_err(|err| format!("on_attestation for an attestation carried in {name}: {err:?}"))?;
    }
    for attester_slashing in &attester_slashings {
        fork_choice::on_attester_slashing(store, attester_slashing).map_err(|err| {
            format!("on_attester_slashing for a slashing carried in {name}: {err:?}")
        })?;
    }

    Ok(())
}

/// Builds the store from the case's anchor and applies every entry of
/// `steps.yaml` in order, stopping at the first one that fails.
fn run_case(case: &Case, config: &Config) -> Result<(), String> {
    let anchor_state = BeaconState::from_ssz(case.fork, &case.ssz_bytes("anchor_state"))
        .map_err(|err| format!("decoding anchor_state: {err:?}"))?;
    let anchor_block = super::fork_choice::decode_anchor_block(case)?;

    let backend = Arc::new(ethlambda_storage::backend::InMemoryBackend::new());
    let mut store = fork_choice::get_forkchoice_store(backend, anchor_state, anchor_block, config)
        .map_err(|err| format!("get_forkchoice_store: {err:?}"))?;

    let steps: Vec<Step> = case.yaml("steps");
    for (index, step) in steps.iter().enumerate() {
        let outcome = match &step.checks {
            Some(checks) => super::fork_choice::apply_checks(&mut store, checks, config),
            None => apply_step(&mut store, case, step, config),
        };
        outcome.map_err(|err| format!("step {index}: {err}"))?;
    }

    Ok(())
}

/// The handler half of [`collect_all_handlers`]'s pair is discarded: every case
/// in this suite runs through [`run_case`] the same way regardless of which
/// handler it came from.
pub fn trials() -> Vec<Trial> {
    let config = Arc::new(Config::active());
    let cases = collect_all_handlers(PRESET, "sync");
    let mut trials = vec![super::discovery_trial("sync", cases.len())];

    for (_handler, case) in cases {
        let config = Arc::clone(&config);
        trials.push(super::case_trial("sync", case, move |case| {
            run_case(case, &config)
        }));
    }

    trials
}
