//! The `fork_choice` runner.
//!
//! Exercises `specs/phase0/fork-choice.md` end to end, plus every later
//! fork's modifications to it. Each case builds a [`Store`] from an anchor
//! state and block via [`fork_choice::get_forkchoice_store`], then replays
//! `steps.yaml` in order. A step is one of `tick`, `block`, `attestation`,
//! `attester_slashing`, `on_merge_block` (bellatrix's own `pow_block` step),
//! or gloas's `execution_payload` and `payload_attestation_message`, driving
//! the correspondingly named handler, or `checks`, which asserts on the
//! store's own fields and on [`fork_choice::get_head`] and
//! [`fork_choice::get_proposer_head`] (gloas adds the head's payload status,
//! the two payload committee vote checks and the viable leaf weights). Each
//! case runs against [`super::case_config`]. See
//! `tests/formats/fork_choice/README.md` in the pinned specification checkout
//! for the format in full.
//!
//! No released fixture targets phase0 directly: the earliest suite is
//! altair's, built from altair-shaped states because the generator needs a
//! later fork's containers even though altair changes nothing about fork
//! choice itself. This runner is gated on [`HIGHEST_IMPLEMENTED_FORK`] like
//! every other, so it picks up a phase0 suite automatically should a future
//! release add one, and a later fork's automatically once this crate catches
//! up to it.
//!
//! # A step's `valid: false` means the call must be rejected
//!
//! Matching [`super::check_transition`]'s rule for a missing `post` state,
//! `valid: false` on a `block`, `attestation`, `attester_slashing`,
//! `execution_payload`, or `payload_attestation_message` step means the
//! handler must return an error, and the store must be left exactly as it
//! was; treating a should-fail call that happens to succeed as a pass would
//! let this suite go green while checking nothing. `on_tick` cannot fail in
//! this crate, nor in the specification (it has no assertion to fail), so a
//! `tick` step asking for rejection is reported as a failure of this suite's
//! own assumptions rather than silently accepted.
//!
//! # Gloas payload attestations are not replayed here
//!
//! The README has the harness expand a gloas block's `payload_attestations`
//! into messages and apply them with `is_from_block` set.
//! [`fork_choice::on_block`] already does that through `notify_ptc_messages`,
//! so expanding them again in [`apply_block`] is redundant: writing the same
//! vote a second time changes nothing.
//!
//! # `viable_for_head_roots_and_weights` is compared as a set
//!
//! The reference generator (`get_viable_for_head_checks` in
//! `tests/core/pyspec/eth_consensus_specs/test/helpers/fork_choice.py`) walks
//! from the justified root's PENDING node with a stack, through
//! `get_node_children` over `get_filtered_block_tree`, and reports every leaf
//! with its `get_weight` and payload status. [`check_viable_for_head`] does the
//! same walk but compares `{root, weight, payload_status}` as an unordered set,
//! since the order the fixture lists the leaves in is not reproducible here:
//! `get_node_children` iterates a `HashMap`, while the generator walks dicts
//! in insertion order.
//! Only gloas cases name it; the walk needs gloas's payload-aware nodes.
//!
//! # An `on_block` step implies more than the README documents
//!
//! `tests/formats/fork_choice/README.md` says a successful `block` step
//! replays every attestation in the block's body through `on_attestation`
//! (with `is_from_block` true) once the block itself is accepted. The
//! reference test generator does one more thing the README omits: it also
//! replays every attester slashing in the block's body through
//! `on_attester_slashing`. See `add_block` in the pinned specification
//! checkout's `tests/core/pyspec/eth2spec/test/helpers/fork_choice.py`. Every
//! released fixture was generated against that code, not just the README's
//! prose, so skipping the slashing half would silently diverge from what a
//! case's later `checks` actually expect. [`apply_block`] does both.
//!
//! # `electra` and `fulu` need a different attestation and slashing shape
//!
//! `phase0::Attestation`/`phase0::AttesterSlashing` decode phase0 through
//! deneb's blocks and standalone `attestation_<root>`/
//! `attester_slashing_<root>` files unchanged; electra and fulu need
//! `electra::Attestation`/`electra::AttesterSlashing` instead (EIP-7549). Both
//! [`fork_choice::Attestation`] and [`fork_choice::AttesterSlashing`] wrap the
//! two shapes, so [`decode_attestation`] and [`decode_attester_slashing`]
//! each dispatch on `case.fork` once, matching how [`decode_anchor_block`]
//! already dispatches for blocks. A block's own body is read through
//! [`fork_choice::block_operations`], which makes that same dispatch beside
//! the two enums it builds, so this runner and the chain actor cannot
//! disagree about a fork's attestation shape.
//!
//! # Checks this runner does not model
//!
//! Every key of a `checks` step this runner models is a field of [`Checks`],
//! which rejects unknown keys, so a check the runner does not model fails its
//! case instead of being dropped without a word.
//!
//! # `columns: []` means "simulate unavailable", not "vacuously available"
//!
//! Fulu's own `is_data_available` (`specs/fulu/fork-choice.md`) is `all(...
//! for column_sidecar in column_sidecars)`, which is vacuously true over an
//! empty list. The reference test generator's own mock of
//! `retrieve_column_sidecars` disagrees on purpose: `with_blob_data_fulu` in
//! `tests/core/pyspec/eth2spec/test/helpers/fork_choice.py` asserts `False`
//! ("Simulation: not all required columns have been sampled") whenever it is
//! asked to return zero sidecars, rather than returning the empty list
//! literally. So a `columns: []` field on a `block` step means the block
//! must be rejected before this crate's own `is_data_available` ever runs;
//! [`block_blob_evidence`] enforces that directly, rather than trusting
//! [`fork_choice::is_data_available_columns`] to reject it (it will not: an
//! absent `columns` field, meaning a block that never samples any column at
//! all, has to reach that same vacuous truth for an ordinary non-blob block
//! to validate).
//!
//! # `anchor_block.ssz_snappy` is unsigned; `get_forkchoice_store` wants signed
//!
//! [`fork_choice::get_forkchoice_store`] takes a [`SignedBeaconBlock`],
//! matching what the store holds blocks as (see that module's own
//! documentation for why the store holds a signed block at all). The fixture's
//! `anchor_block.ssz_snappy` is an unsigned `BeaconBlock`, so
//! [`decode_anchor_block`] decodes it as the fork's own unsigned container
//! and wraps it in a zero-signature signed one; the anchor block's signature
//! is never actually checked, since a trusted anchor is not verified against
//! anything. A `block` step's own file is already a signed block, so
//! [`decode_signed_block`] just decodes it directly through
//! [`SignedBeaconBlock::from_ssz`].

use std::sync::Arc;

use ethlambda_state_transition::beacon::ForkName;
use ethlambda_state_transition::beacon::config::Config;
use ethlambda_state_transition::beacon::containers::{
    BeaconState, Checkpoint, SignedBeaconBlock, altair, bellatrix, capella, deneb, electra, fulu,
    gloas, phase0,
};
use ethlambda_state_transition::beacon::fork_choice::{
    self, DataAvailability, ForkChoiceNode, PayloadStatus, Store,
};
use ethlambda_state_transition::beacon::helpers::accessors::CommitteeCache;
use ethlambda_state_transition::beacon::preset;
use ethlambda_state_transition::beacon::primitives::{KzgProof, Root};
use ethlambda_state_transition::beacon::stf::ExecutionEngine;
use libssz::SszDecode;
use libssz_types::SszList;
use libtest_mimic::Trial;

use super::{Case, PRESET, collect_all_handlers, lean_is_not_a_fixture_fork};

// ---------------------------------------------------------------------------
// `steps.yaml` deserialization
// ---------------------------------------------------------------------------

/// One entry of a case's `steps.yaml`.
///
/// The format overlays eight step kinds into one YAML sequence item: exactly
/// one of [`Step::tick`], [`Step::block`], [`Step::attestation`],
/// [`Step::attester_slashing`], [`Step::pow_block`],
/// [`Step::execution_payload`], and [`Step::payload_attestation_message`] is
/// set for an execution step, or none of them for a [`Step::checks`] step.
/// Modeled as one struct with every field optional, rather than a
/// `#[serde(untagged)]` enum over seven variants, because the execution kinds
/// that carry a validity outcome also share [`Step::valid`], which an enum
/// would have to repeat on every variant instead of naming once.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    /// The Unix-second time to advance the store to, for an `on_tick` step.
    tick: Option<u64>,
    /// The `block_<root>` file naming the block for an `on_block` step.
    block: Option<String>,
    /// `[New in Deneb/Electra]` the `blobs_<root>` file naming this `block`
    /// step's blob evidence, paired positionally with [`Step::proofs`].
    blobs: Option<String>,
    /// `[New in Deneb/Electra]` this `block` step's proofs, one per blob in
    /// [`Step::blobs`], as `0x`-prefixed byte48 hex strings rather than a
    /// separate file.
    proofs: Option<Vec<String>>,
    /// `[New in Fulu]` the `column_<root>` files naming this `block` step's
    /// column evidence, replacing [`Step::blobs`]/[`Step::proofs`]. See the
    /// module documentation for why an empty (but present) list is not the
    /// same as an absent one.
    columns: Option<Vec<String>>,
    /// The `attestation_<root>` file naming the attestation for an
    /// `on_attestation` step.
    attestation: Option<String>,
    /// The `attester_slashing_<root>` file naming the slashing for an
    /// `on_attester_slashing` step.
    attester_slashing: Option<String>,
    /// `[New in Bellatrix]` the `pow_block_<root>` file naming the PoW block
    /// an `on_merge_block` step adds to the store for later `get_pow_block`
    /// lookups.
    pow_block: Option<String>,
    /// `[New in Gloas]` the `execution_payload_envelope_<root>` file naming the
    /// envelope an `on_execution_payload_envelope` step delivers.
    execution_payload: Option<String>,
    /// `[New in Gloas]` the `payload_attestation_message_<root>` file naming
    /// the message an `on_payload_attestation_message` step delivers.
    payload_attestation_message: Option<String>,
    /// Whether this step's call is expected to succeed. Only `block`,
    /// `attestation`, `attester_slashing`, `execution_payload`, and
    /// `payload_attestation_message` steps carry `false` in any released
    /// fixture, but the format allows it on any execution step.
    #[serde(default = "default_valid")]
    valid: bool,
    /// The assertions to check against the current store.
    checks: Option<Checks>,
}

/// [`Step::valid`]'s default: a step not naming its own validity is expected
/// to succeed.
fn default_valid() -> bool {
    true
}

/// A `checks` step's assertions against the store.
///
/// Every field of the format's `checks` step is modeled, and unknown keys are
/// rejected, so a key added to the format fails its case instead of being
/// dropped.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Checks {
    time: Option<u64>,
    genesis_time: Option<u64>,
    head: Option<HeadCheck>,
    justified_checkpoint: Option<CheckpointCheck>,
    finalized_checkpoint: Option<CheckpointCheck>,
    proposer_boost_root: Option<String>,
    get_proposer_head: Option<String>,
    /// `[New in Gloas]` the PTC's payload timeliness votes for one block.
    payload_timeliness_vote: Option<VoteCheck>,
    /// `[New in Gloas]` the PTC's blob data availability votes for one block.
    payload_data_availability_vote: Option<VoteCheck>,
    /// `[New in Gloas]` the payload-aware leaves of the filtered block tree,
    /// with their weights, in the generator's own order.
    viable_for_head_roots_and_weights: Option<Vec<ViableLeafCheck>>,
}

/// One leaf of `viable_for_head_roots_and_weights`.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ViableLeafCheck {
    root: String,
    weight: u64,
    /// Required on purpose: only gloas cases name this check, so a
    /// pre-gloas-shaped leaf without a payload status fails to parse.
    payload_status: u8,
}

/// The expected votes of one block's payload committee, ordered by PTC
/// position, with `null` for a position that has not voted.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct VoteCheck {
    block_root: String,
    votes: Vec<Option<bool>>,
}

/// The expected value of [`fork_choice::get_head`], as `checks.head` gives it:
/// the root and, redundantly, the slot of the block it names.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadCheck {
    slot: u64,
    root: String,
    /// `[New in Gloas]` the head node's payload status, as its discriminant.
    payload_status: Option<u8>,
}

/// The expected value of a checkpoint field (`justified_checkpoint` or
/// `finalized_checkpoint`).
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointCheck {
    epoch: u64,
    root: String,
}

/// Parses a fixture's `0x`-prefixed hex root.
///
/// Duplicated from `ssz_static`'s private helper of the same purpose rather
/// than shared, matching how each runner in this test suite is otherwise
/// self-contained.
fn parse_root(hex_root: &str) -> Root {
    let stripped = hex_root.strip_prefix("0x").unwrap_or(hex_root);
    let bytes = hex::decode(stripped).expect("the fixture's root is valid hex");
    Root::from_slice(&bytes)
}

/// Parses a fixture's `0x`-prefixed byte48 hex string into a [`KzgProof`],
/// the shape a `block` step's inline `proofs` field carries them in rather
/// than a separate file.
fn parse_kzg_proof(hex_proof: &str) -> KzgProof {
    let stripped = hex_proof.strip_prefix("0x").unwrap_or(hex_proof);
    let bytes = hex::decode(stripped).expect("the fixture's proof is valid hex");
    KzgProof(
        bytes
            .try_into()
            .expect("a KZG proof is KZG_POINT_SIZE bytes"),
    )
}

// ---------------------------------------------------------------------------
// Decoding blocks, attestations, and slashings
// ---------------------------------------------------------------------------

/// Decodes `<name>.ssz_snappy` as `T`, turning a decode failure into a case
/// failure rather than a panic: a block, attestation, or slashing this crate
/// cannot parse is exactly the kind of thing this suite exists to catch.
fn decode<T: SszDecode>(case: &Case, name: &str) -> Result<T, String> {
    T::from_ssz_bytes(&case.ssz_bytes(name)).map_err(|err| format!("decoding {name}: {err:?}"))
}

/// Decodes `anchor_block.ssz_snappy` for [`fork_choice::get_forkchoice_store`].
///
/// The file is an unsigned `BeaconBlock`; see the module documentation for
/// why this wraps it in a signed container with a zero signature rather than
/// decoding straight into one. `ForkName::Fulu` decodes as
/// [`electra::SignedBeaconBlock`], matching how [`SignedBeaconBlock::Fulu`]
/// wraps that same type rather than a `fulu`-specific one.
pub(super) fn decode_anchor_block(case: &Case) -> Result<SignedBeaconBlock, String> {
    match case.fork {
        ForkName::Phase0 => Ok(SignedBeaconBlock::Phase0(phase0::SignedBeaconBlock {
            message: decode(case, "anchor_block")?,
            signature: Default::default(),
        })),
        ForkName::Altair => Ok(SignedBeaconBlock::Altair(altair::SignedBeaconBlock {
            message: decode(case, "anchor_block")?,
            signature: Default::default(),
        })),
        ForkName::Bellatrix => Ok(SignedBeaconBlock::Bellatrix(bellatrix::SignedBeaconBlock {
            message: decode(case, "anchor_block")?,
            signature: Default::default(),
        })),
        ForkName::Capella => Ok(SignedBeaconBlock::Capella(capella::SignedBeaconBlock {
            message: decode(case, "anchor_block")?,
            signature: Default::default(),
        })),
        ForkName::Deneb => Ok(SignedBeaconBlock::Deneb(deneb::SignedBeaconBlock {
            message: decode(case, "anchor_block")?,
            signature: Default::default(),
        })),
        ForkName::Electra => Ok(SignedBeaconBlock::Electra(electra::SignedBeaconBlock {
            message: decode(case, "anchor_block")?,
            signature: Default::default(),
        })),
        ForkName::Fulu => Ok(SignedBeaconBlock::Fulu(electra::SignedBeaconBlock {
            message: decode(case, "anchor_block")?,
            signature: Default::default(),
        })),
        ForkName::Gloas => Ok(SignedBeaconBlock::Gloas(gloas::SignedBeaconBlock {
            message: decode(case, "anchor_block")?,
            signature: Default::default(),
        })),
        ForkName::Lean => lean_is_not_a_fixture_fork("fork_choice"),
    }
}

/// Decodes a `block_<root>.ssz_snappy` file named by an `on_block` step. The
/// file is already a signed block of the case's own fork, so this is a
/// direct decode through the fork-generic decoder, unlike
/// [`decode_anchor_block`].
pub(super) fn decode_signed_block(case: &Case, name: &str) -> Result<SignedBeaconBlock, String> {
    SignedBeaconBlock::from_ssz(case.fork, &case.ssz_bytes(name))
        .map_err(|err| format!("decoding {name}: {err:?}"))
}

/// Decodes an `attestation_<root>.ssz_snappy` file, in whichever of
/// [`fork_choice::Attestation`]'s two shapes `case.fork` needs. See the
/// module documentation for why electra and fulu need
/// [`electra::Attestation`] rather than [`phase0::Attestation`].
fn decode_attestation(case: &Case, name: &str) -> Result<fork_choice::Attestation, String> {
    match case.fork {
        ForkName::Electra | ForkName::Fulu => {
            Ok(fork_choice::Attestation::Electra(decode(case, name)?))
        }
        ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb => Ok(fork_choice::Attestation::Phase0(decode(case, name)?)),
        ForkName::Gloas => Ok(fork_choice::Attestation::Gloas(decode(case, name)?)),
        ForkName::Lean => lean_is_not_a_fixture_fork("fork_choice"),
    }
}

/// Decodes an `attester_slashing_<root>.ssz_snappy` file. See
/// [`decode_attestation`] for why the fork decides the shape.
fn decode_attester_slashing(
    case: &Case,
    name: &str,
) -> Result<fork_choice::AttesterSlashing, String> {
    match case.fork {
        ForkName::Electra | ForkName::Fulu => {
            Ok(fork_choice::AttesterSlashing::Electra(decode(case, name)?))
        }
        ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb => Ok(fork_choice::AttesterSlashing::Phase0(decode(case, name)?)),
        ForkName::Gloas => Ok(fork_choice::AttesterSlashing::Gloas(decode(case, name)?)),
        ForkName::Lean => lean_is_not_a_fixture_fork("fork_choice"),
    }
}

/// Decodes a `pow_block_<root>.ssz_snappy` file named by an `on_merge_block`
/// step.
fn decode_pow_block(case: &Case, name: &str) -> Result<fork_choice::PowBlock, String> {
    decode(case, name)
}

/// Extracts a `block` step's blob evidence, if it carries any: deneb and
/// electra's `blobs`/`proofs` fields, or fulu's `columns` field. Absent
/// either, this is [`DataAvailability::NotRequired`], the right value for
/// every pre-deneb block and for a later-fork block with no blob
/// commitments.
///
/// See the module documentation for why an empty (but present) `columns`
/// list is rejected directly here rather than passed through to
/// [`fork_choice::is_data_available_columns`].
fn block_blob_evidence(case: &Case, step: &Step) -> Result<DataAvailability, String> {
    if let Some(names) = &step.columns {
        if names.is_empty() {
            return Err(
                "columns: [] simulates the reference generator's retrieve_column_sidecars \
                 raising \"not all required columns have been sampled\" (see this runner's \
                 module documentation), so the block must be rejected before \
                 is_data_available_columns ever runs"
                    .to_string(),
            );
        }
        let sidecars = names
            .iter()
            .map(|name| decode::<fulu::DataColumnSidecar>(case, name))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(DataAvailability::Columns(sidecars));
    }

    if let Some(name) = &step.blobs {
        let blobs: SszList<deneb::Blob, { preset::MAX_BLOB_COMMITMENTS_PER_BLOCK }> =
            case.ssz(name);
        let proofs = step
            .proofs
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|hex_proof| parse_kzg_proof(hex_proof))
            .collect();
        return Ok(DataAvailability::Blobs {
            blobs: blobs.into_inner(),
            proofs,
        });
    }

    Ok(DataAvailability::NotRequired)
}

// ---------------------------------------------------------------------------
// Applying a step
// ---------------------------------------------------------------------------

/// Applies one `block` step: decodes the named file and its blob evidence,
/// calls `on_block`, and, only if the block was accepted, replays every
/// attestation and attester slashing carried in its body. See the module
/// documentation for why the slashing half belongs here even though the
/// format's own README omits it.
///
/// `committees` is the case's one [`CommitteeCache`], shared by every step as
/// the node's chain actor shares its own across imports; see [`run_case`].
fn apply_block(
    store: &mut Store,
    case: &Case,
    step: &Step,
    name: &str,
    expect_valid: bool,
    config: &Config,
    committees: &CommitteeCache,
) -> Result<(), String> {
    let signed_block = decode_signed_block(case, name)?;

    let blob_evidence = match block_blob_evidence(case, step) {
        Ok(evidence) => evidence,
        // A simulated-unavailable `columns: []` never even reaches
        // `on_block` (see `block_blob_evidence`'s documentation), but the
        // fixture is asking about exactly the same "was this block
        // rejected" question `on_block`'s own `Err` below answers, so this
        // is folded into the same `expect_valid` check rather than treated
        // as this suite's own setup failing.
        Err(simulated_unavailable) => {
            return if expect_valid {
                Err(format!("{name} was rejected: {simulated_unavailable}"))
            } else {
                Ok(())
            };
        }
    };
    // Collected before `on_block` moves `signed_block` in, so they are still
    // available for the replay below after a successful call.
    let (attestations, attester_slashings) = fork_choice::block_operations(&signed_block);

    match (
        fork_choice::on_block(
            store,
            signed_block,
            config,
            &blob_evidence,
            &fork_choice::PayloadValidity::NotRequired,
            committees,
        ),
        expect_valid,
    ) {
        (Ok(()), false) => {
            return Err(format!(
                "{name} was accepted, but the step expects it to be rejected"
            ));
        }
        (Err(err), true) => return Err(format!("{name} was rejected: {err:?}")),
        // Correctly rejected: the handler's contract leaves `store` untouched,
        // so there is nothing from this block left to replay.
        (Err(_), false) => return Ok(()),
        (Ok(()), true) => {}
    }

    for attestation in &attestations {
        fork_choice::on_attestation(store, attestation, true, config, committees).map_err(
            |err| format!("on_attestation for an attestation carried in {name}: {err:?}"),
        )?;
    }
    for attester_slashing in &attester_slashings {
        fork_choice::on_attester_slashing(store, attester_slashing).map_err(|err| {
            format!("on_attester_slashing for a slashing carried in {name}: {err:?}")
        })?;
    }

    Ok(())
}

/// Turns a handler's outcome into a step's verdict: `valid: true` needs `Ok`,
/// `valid: false` needs `Err`, and either mismatch names the file.
fn expect_outcome<E: std::fmt::Debug>(
    name: &str,
    outcome: Result<(), E>,
    valid: bool,
) -> Result<(), String> {
    match (outcome, valid) {
        (Ok(()), false) => Err(format!(
            "{name} was accepted, but the step expects it to be rejected"
        )),
        (Err(err), true) => Err(format!("{name} was rejected: {err:?}")),
        (Ok(()), true) | (Err(_), false) => Ok(()),
    }
}

/// Applies one non-`checks` execution step, dispatching on which of
/// [`Step::tick`], [`Step::block`], [`Step::attestation`],
/// [`Step::attester_slashing`], [`Step::pow_block`],
/// [`Step::execution_payload`], or [`Step::payload_attestation_message`] is
/// set.
fn apply_execution_step(
    store: &mut Store,
    case: &Case,
    step: &Step,
    config: &Config,
    committees: &CommitteeCache,
) -> Result<(), String> {
    if let Some(time) = step.tick {
        if !step.valid {
            // The specification's `on_tick` has no assertion to fail, and
            // neither does this crate's: there is no way to honor a fixture
            // that asked for a rejected tick, so this fails loudly instead of
            // quietly treating the step as a pass. No released fixture
            // exercises this; see the module documentation.
            return Err(
                "a tick step expects rejection, but on_tick cannot fail in this crate".to_string(),
            );
        }
        fork_choice::on_tick(store, time, config);
        return Ok(());
    }

    if let Some(name) = &step.block {
        return apply_block(store, case, step, name, step.valid, config, committees);
    }

    if let Some(name) = &step.attestation {
        let attestation = decode_attestation(case, name)?;
        return expect_outcome(
            name,
            fork_choice::on_attestation(store, &attestation, false, config, committees),
            step.valid,
        );
    }

    if let Some(name) = &step.attester_slashing {
        let attester_slashing = decode_attester_slashing(case, name)?;
        return expect_outcome(
            name,
            fork_choice::on_attester_slashing(store, &attester_slashing),
            step.valid,
        );
    }

    if let Some(name) = &step.pow_block {
        // No validity outcome to honor here: an `on_merge_block` step only
        // ever adds data a fixture suite already trusts (see
        // `fork_choice::insert_pow_block`'s own documentation), so there is
        // nothing for `step.valid` to mean.
        let pow_block = decode_pow_block(case, name)?;
        fork_choice::insert_pow_block(store, pow_block);
        return Ok(());
    }

    if let Some(name) = &step.execution_payload {
        let signed_envelope: gloas::SignedExecutionPayloadEnvelope = decode(case, name)?;
        // The format names no sampled columns for this step, so the evidence
        // is the empty retrieval, which reads as available.
        return expect_outcome(
            name,
            fork_choice::on_execution_payload_envelope(
                store,
                &signed_envelope,
                config,
                &[],
                &ExecutionEngine::valid(),
            ),
            step.valid,
        );
    }

    if let Some(name) = &step.payload_attestation_message {
        let ptc_message: gloas::PayloadAttestationMessage = decode(case, name)?;
        return expect_outcome(
            name,
            fork_choice::on_payload_attestation_message(store, &ptc_message, false, config),
            step.valid,
        );
    }

    Err(
        "step has none of tick, block, attestation, attester_slashing, pow_block, \
         execution_payload, or payload_attestation_message set"
            .to_string(),
    )
}

// ---------------------------------------------------------------------------
// Checking the store
// ---------------------------------------------------------------------------

/// Checks one scalar field against its expected value.
fn check_u64(label: &str, expected: u64, actual: u64) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label}: expected {expected}, got {actual}"))
    }
}

/// Checks one root-valued field against its expected, hex-encoded value.
fn check_root(label: &str, expected_hex: &str, actual: Root) -> Result<(), String> {
    let expected = parse_root(expected_hex);
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{label}: expected 0x{}, got 0x{}",
            hex::encode(expected.0),
            hex::encode(actual.0),
        ))
    }
}

/// Checks `justified_checkpoint` or `finalized_checkpoint` against its
/// expected epoch and root.
fn check_checkpoint(
    label: &str,
    expected: &CheckpointCheck,
    actual: Checkpoint,
) -> Result<(), String> {
    let expected_checkpoint = Checkpoint {
        epoch: expected.epoch,
        root: parse_root(&expected.root),
    };
    if actual == expected_checkpoint {
        Ok(())
    } else {
        Err(format!(
            "{label}: expected {{epoch: {}, root: 0x{}}}, got {{epoch: {}, root: 0x{}}}",
            expected_checkpoint.epoch,
            hex::encode(expected_checkpoint.root.0),
            actual.epoch,
            hex::encode(actual.root.0),
        ))
    }
}

/// Checks `head` against [`fork_choice::get_head`]'s root, and that root's
/// slot (read through [`fork_choice::get_forkchoice_store`]'s store) against
/// the fixture's redundant `slot` field.
fn check_head(expected: &HeadCheck, store: &mut Store, config: &Config) -> Result<(), String> {
    let actual_root =
        fork_choice::get_head(store, config).map_err(|err| format!("get_head: {err:?}"))?;
    let actual_slot = store
        .get_signed_block(&actual_root)
        .expect("get")
        .map(|block| block.slot())
        .ok_or_else(|| {
            format!(
                "get_head returned 0x{}, which is not in store.blocks",
                hex::encode(actual_root.0)
            )
        })?;

    let expected_root = parse_root(&expected.root);
    if actual_root != expected_root || actual_slot != expected.slot {
        return Err(format!(
            "head: expected {{slot: {}, root: 0x{}}}, got {{slot: {actual_slot}, root: 0x{}}}",
            expected.slot,
            hex::encode(expected_root.0),
            hex::encode(actual_root.0),
        ));
    }
    if let Some(expected_status) = expected.payload_status {
        let node = fork_choice::get_head_node(store, config)
            .map_err(|err| format!("get_head_node: {err:?}"))?;
        if node.payload_status as u8 != expected_status {
            return Err(format!(
                "head payload_status: expected {expected_status}, got {} (head 0x{})",
                node.payload_status as u8,
                hex::encode(node.root.0)
            ));
        }
    }
    Ok(())
}

/// Checks `get_proposer_head`, computed the same way the reference test
/// harness does: from the current head and current slot, not a value the
/// fixture supplies separately.
fn check_get_proposer_head(
    expected_hex: &str,
    store: &mut Store,
    config: &Config,
    committees: &CommitteeCache,
) -> Result<(), String> {
    let head = fork_choice::get_head(store, config).map_err(|err| format!("get_head: {err:?}"))?;
    let slot = fork_choice::get_current_slot(store, config);
    let actual = fork_choice::get_proposer_head(store, head, slot, config, committees)
        .map_err(|err| format!("get_proposer_head: {err:?}"))?;
    check_root("get_proposer_head", expected_hex, actual)
}

/// Checks one of the two PTC vote fields (`payload_timeliness_vote` or
/// `payload_data_availability_vote`) against the store's votes for the named
/// block, position by position.
fn check_votes(
    label: &str,
    expected: &VoteCheck,
    actual: Option<Vec<Option<bool>>>,
) -> Result<(), String> {
    let block_root = parse_root(&expected.block_root);
    let actual =
        actual.ok_or_else(|| format!("{label}: no votes for 0x{}", hex::encode(block_root.0)))?;
    if actual == expected.votes {
        Ok(())
    } else {
        Err(format!(
            "{label} for 0x{}: expected {:?}, got {actual:?}",
            hex::encode(block_root.0),
            expected.votes
        ))
    }
}

/// Checks `viable_for_head_roots_and_weights`: the leaves of the payload-aware
/// tree under the justified root, each with its weight and payload status.
///
/// See the module documentation for why the comparison ignores order.
fn check_viable_for_head(
    expected: &[ViableLeafCheck],
    store: &Store,
    config: &Config,
    committees: &CommitteeCache,
) -> Result<(), String> {
    let index = store.block_index();
    let blocks = fork_choice::get_filtered_block_tree(store, &index, config).map_err(|err| {
        format!("viable_for_head_roots_and_weights: get_filtered_block_tree: {err:?}")
    })?;
    let mut pending = vec![ForkChoiceNode {
        root: store.beacon_justified_checkpoint().root,
        payload_status: PayloadStatus::Pending,
    }];
    let mut actual: Vec<(Root, u64, u8)> = Vec::new();
    while let Some(node) = pending.pop() {
        let children = fork_choice::get_node_children(store, &blocks, node).map_err(|err| {
            format!("viable_for_head_roots_and_weights: get_node_children: {err:?}")
        })?;
        if children.is_empty() {
            let weight = fork_choice::gloas_get_weight(store, node, config, committees)
                .map_err(|err| format!("viable_for_head_roots_and_weights: get_weight: {err:?}"))?;
            actual.push((node.root, weight, node.payload_status as u8));
        } else {
            pending.extend(children);
        }
    }
    let mut expected: Vec<(Root, u64, u8)> = expected
        .iter()
        .map(|leaf| (parse_root(&leaf.root), leaf.weight, leaf.payload_status))
        .collect();
    expected.sort();
    actual.sort();
    if actual == expected {
        Ok(())
    } else {
        let show = |leaves: &[(Root, u64, u8)]| {
            leaves
                .iter()
                .map(|(root, weight, status)| {
                    format!("{{0x{}, {weight}, {status}}}", hex::encode(root.0))
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        Err(format!(
            "viable_for_head_roots_and_weights: expected [{}], got [{}]",
            show(&expected),
            show(&actual)
        ))
    }
}

/// Applies one `checks` step: every field the fixture sets must match.
pub(super) fn apply_checks(
    store: &mut Store,
    checks: &Checks,
    config: &Config,
    committees: &CommitteeCache,
) -> Result<(), String> {
    if let Some(expected) = checks.time {
        // The fixture's `time` is the specification's seconds; the store keeps
        // one millisecond row for both chains, so the caller converts.
        let time_seconds = store.time_ms().expect("store time exists") / 1_000;
        check_u64("time", expected, time_seconds)?;
    }
    if let Some(expected) = checks.genesis_time {
        check_u64("genesis_time", expected, store.config().genesis_time)?;
    }
    if let Some(expected) = &checks.justified_checkpoint {
        check_checkpoint(
            "justified_checkpoint",
            expected,
            store.beacon_justified_checkpoint(),
        )?;
    }
    if let Some(expected) = &checks.finalized_checkpoint {
        check_checkpoint(
            "finalized_checkpoint",
            expected,
            store.beacon_finalized_checkpoint(),
        )?;
    }
    if let Some(expected) = &checks.proposer_boost_root {
        check_root("proposer_boost_root", expected, store.proposer_boost_root())?;
    }
    if let Some(expected) = &checks.head {
        check_head(expected, store, config)?;
    }
    if let Some(expected) = &checks.payload_timeliness_vote {
        let actual = store.payload_timeliness_vote(&parse_root(&expected.block_root));
        check_votes("payload_timeliness_vote", expected, actual)?;
    }
    if let Some(expected) = &checks.payload_data_availability_vote {
        let actual = store.payload_data_availability_vote(&parse_root(&expected.block_root));
        check_votes("payload_data_availability_vote", expected, actual)?;
    }
    if let Some(expected) = &checks.viable_for_head_roots_and_weights {
        check_viable_for_head(expected, store, config, committees)?;
    }
    if let Some(expected) = &checks.get_proposer_head {
        check_get_proposer_head(expected, store, config, committees)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Running a case
// ---------------------------------------------------------------------------

/// Runs one case: builds the store from its anchor, then applies every step
/// in `steps.yaml` in order, stopping at the first one that fails.
///
/// Stopping rather than continuing matches how a rejected call leaves `store`
/// untouched but a call that unexpectedly succeeds (or fails) leaves it in a
/// state the fixture's remaining steps were never written to expect; nothing
/// past that point would be checking anything meaningful.
///
/// One [`CommitteeCache`] serves the whole case, the way the node's chain
/// actor holds one across every import, rather than a fresh one per call.
/// The fixtures build sibling branches on purpose, and sharing is what puts
/// the cache's key to the test: two states from different branches that
/// agree on an epoch's deciding block share its entry, and if the key ever
/// named a shuffling one of them does not actually have, a committee here
/// would come out wrong and the case would fail. A fresh cache per call would
/// pass whatever the key did.
fn run_case(case: &Case, config: &Config) -> Result<(), String> {
    let anchor_state = BeaconState::from_ssz(case.fork, &case.ssz_bytes("anchor_state"))
        .map_err(|err| format!("decoding anchor_state: {err:?}"))?;
    let anchor_block = decode_anchor_block(case)?;

    let backend = Arc::new(ethlambda_storage::backend::InMemoryBackend::new());
    let mut store = fork_choice::get_forkchoice_store(backend, anchor_state, anchor_block, config)
        .map_err(|err| format!("get_forkchoice_store: {err:?}"))?;

    let committees = CommitteeCache::default();
    let steps: Vec<Step> = case.yaml("steps");
    for (index, step) in steps.iter().enumerate() {
        let outcome = match &step.checks {
            Some(checks) => apply_checks(&mut store, checks, config, &committees),
            None => apply_execution_step(&mut store, case, step, config, &committees),
        };
        outcome.map_err(|err| format!("step {index}: {err}"))?;
    }

    Ok(())
}

/// The handler half of [`collect_all_handlers`]'s pair is discarded: every
/// case in this suite runs through [`run_case`] the same way regardless of
/// which handler it came from, unlike `ssz_static`, which dispatches on it.
pub fn trials() -> Vec<Trial> {
    let cases = collect_all_handlers(PRESET, "fork_choice");
    let mut trials = vec![super::discovery_trial("fork_choice", cases.len())];

    for (_handler, case) in cases {
        trials.push(super::case_trial("fork_choice", case, |case| {
            run_case(case, &super::case_config(case))
        }));
    }

    trials
}
