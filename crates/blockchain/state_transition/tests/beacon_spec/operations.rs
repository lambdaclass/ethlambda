//! The `operations` runner.
//!
//! Each case holds a `pre` state, one operation, and a `post` state. The absence
//! of `post` is the assertion: the operation must be rejected, and a run that
//! accepts it fails. That makes this suite the crate's main check that invalid
//! input is refused rather than absorbed, so the "expected rejection" path gets
//! as much attention here as the success path.
//!
//! The handler names the operation, and the operation's file is named after the
//! handler, except `block_header` (a whole block), `execution_payload` (a whole
//! body, since checking a payload needs the block's blob commitments and, for
//! deneb on, occasionally the version raising that count), and `withdrawals`
//! (a bare `ExecutionPayload`, since the sweep needs nothing else from the
//! body) and `bls_to_execution_change` (named `address_change` in the fixture
//! tree).
//!
//! Unlike [`super::sanity`], which runs whole blocks through
//! [`ethlambda_state_transition::beacon::stf::state_transition`], this calls each operation's own
//! function directly, so nothing here can lean on `process_block`'s per-fork
//! dispatch: every handler that changed shape or behavior between forks has to
//! be routed to the right function by hand, keyed on [`Case::fork`]. Each
//! routing decision below is justified by a "Modified" or "New" marker in the
//! pinned specification's own table of contents for that fork, not by
//! inspection of this crate's source; a handler with no such marker for a
//! given fork keeps calling whichever earlier fork's function last introduced
//! or changed it.
//!
//! - `proposer_slashing` needs no routing at all: no fork's specification ever
//!   lists a modified `process_proposer_slashing`, so phase0's function serves
//!   every fork this crate implements.
//! - `attester_slashing` and `deposit` need no *function* routing through
//!   deneb (neither fork's specification lists either as modified before
//!   electra), but `attester_slashing`'s container does change shape at
//!   electra (see below), and electra's own specification lists both
//!   `process_attester_slashing` (transcribed against the new container, not
//!   behaviorally different) and `process_deposit` (behaviorally different:
//!   a deposit is queued rather than credited) as its own functions from
//!   there on.
//! - `attestation` needs both. The container
//!   ([`phase0::Attestation`]) is the one phase0, altair, bellatrix, capella,
//!   and deneb all share, and [`electra::Attestation`] (EIP-7549's committee
//!   bitfield) takes over at electra. *How* an attestation is scored changes
//!   twice more within that container-stable range: phase0 defers to the
//!   epoch boundary ([`operations::process_attestation`]), altair scores it
//!   immediately ([`altair_stf::process_attestation`]) and that version
//!   serves bellatrix and capella too since neither fork's specification
//!   modifies it again, and deneb widens the inclusion window and the
//!   timely-target condition (EIP-7045) with its own version
//!   ([`deneb_stf::process_attestation`]). Calling an earlier fork's version
//!   on a later case would not even fail loudly in every instance, since it
//!   would return [`ethlambda_state_transition::beacon::Error::UnsupportedForFork`] only where
//!   the two forks' state shapes actually differ, which is still a rejection,
//!   just not the one the fixture is testing for.
//! - `voluntary_exit` changes twice after phase0: deneb pins the signature to
//!   a fixed fork version for EIP-7044, and electra adds a
//!   pending-partial-withdrawal check and swaps in electra's own
//!   exit-queue accounting for EIP-7251.
//! - `block_header`'s file is a whole `BeaconBlock`, and that type is
//!   different per fork (altair's carries a `sync_aggregate` its body root
//!   folds in, bellatrix's an execution payload on top of that, and so on).
//!   [`block::process_block_header`] itself takes only the four
//!   fork-invariant fields a header needs, not a block, precisely so this
//!   runner (and every per-fork `process_block_*` driver) can decode with the
//!   fork's own concrete type and still call one shared function.
//! - `sync_aggregate` is new in altair, with no phase0 case, and no later
//!   fork's specification ever lists a modified version of it, so it needs
//!   no fork match beyond that.
//! - `execution_payload` is new in bellatrix and its specification lists a
//!   modified version at every fork from capella on: capella and later drop
//!   the still-mid-merge-transition check, deneb folds in the blob
//!   commitment count, electra reads a different configuration field for
//!   that same count, and fulu reads a schedule instead of a fixed field.
//!   Five forks, five distinct functions, none reusable for another fork's
//!   case.
//! - `bls_to_execution_change` and `withdrawals` are both new in capella.
//!   `bls_to_execution_change` is never listed as modified again: its
//!   function reads and writes only fork-invariant fields, so capella's own
//!   serves every later fork too. `withdrawals` is listed as modified once
//!   more, at electra (EIP-7251's partial-withdrawal queue); deneb's own
//!   specification lists no change to it at all, so deneb's copy exists only
//!   to hold a differently-typed `payload` parameter, not different logic.
//! - `consolidation_request`, `deposit_request`, and `withdrawal_request` are
//!   all new in electra, alongside `withdrawals`, `process_attestation`,
//!   `process_deposit`, and `process_voluntary_exit`. Fulu's specification
//!   lists `consolidation_request`, `withdrawal_request`, `withdrawals`,
//!   `process_attestation`, and `process_voluntary_exit` as unmodified, so
//!   electra's functions serve fulu's cases for those five too, and it lists
//!   `process_deposit` as removed outright rather than modified (beta.2 ships
//!   no fulu `operations/deposit` fixtures, so that arm is untested either
//!   way). `deposit_request` is the one exception with a genuine fulu-only
//!   function: it drops the statement that sets
//!   `deposit_requests_start_index`, since fulu retires the eth1-bridge
//!   deposit mechanism outright (`fulu_stf::process_deposit_request`'s own
//!   doc).
//! - `execution_payload_bid` and `parent_execution_payload` are new in gloas,
//!   the block's binding commitment to a builder's payload and the next
//!   block's processing of the previous one (EIP-7732); neither exists on any
//!   earlier fork. `withdrawals` is modified again at gloas, and this time the
//!   fixture's own operation file changes too: gloas's own
//!   `process_withdrawals(state)` takes no payload at all (withdrawals are now
//!   deterministic from the state alone), so unlike every earlier fork's arm
//!   this one reads no `<input-name>` file and calls `gloas_stf::process_withdrawals`
//!   with only the state.
use std::sync::Arc;

use ethlambda_state_transition::beacon::ForkName;
use ethlambda_state_transition::beacon::config::Config;
use ethlambda_state_transition::beacon::containers::{
    BeaconState, altair, bellatrix, capella, deneb, electra, gloas, phase0, shared,
};
use ethlambda_state_transition::beacon::helpers::accessors::CommitteeCache;
use ethlambda_state_transition::beacon::primitives::HashTreeRoot as _;
use ethlambda_state_transition::beacon::stf::altair as altair_stf;
use ethlambda_state_transition::beacon::stf::bellatrix as bellatrix_stf;
use ethlambda_state_transition::beacon::stf::capella as capella_stf;
use ethlambda_state_transition::beacon::stf::deneb as deneb_stf;
use ethlambda_state_transition::beacon::stf::electra as electra_stf;
use ethlambda_state_transition::beacon::stf::fulu as fulu_stf;
use ethlambda_state_transition::beacon::stf::gloas as gloas_stf;
use ethlambda_state_transition::beacon::stf::{ExecutionEngine, block, operations};
use libtest_mimic::{Failed, Trial};

use super::{Case, PRESET, collect_all_handlers, lean_is_not_a_fixture_fork};

/// The `{execution_valid: bool}` an `execution_payload` case ships alongside
/// its block, standing in for whatever a real execution client would have
/// answered. See [`ExecutionEngine`]'s own documentation for why this crate
/// collapses that whole interface to one boolean.
#[derive(serde::Deserialize)]
struct ExecutionYaml {
    execution_valid: bool,
}

/// Applies one operation to the case's pre-state.
///
/// Returns the post-state on success. Anything the crate rejects comes back as an
/// error, which the caller compares against whether the case has a `post`.
fn apply(
    handler: &str,
    case: &Case,
    state: &mut BeaconState,
    config: &Config,
) -> Result<(), String> {
    // Only the `attestation` handler reads this. Bound up here so each of its
    // calls fits on one line; a case processes a single attestation, so there
    // is nothing for the cache to share between calls.
    let committees = CommitteeCache::default();
    let outcome = match handler {
        // Every fork's own `BeaconBlock` carries a different concrete body
        // (altair's adds a sync aggregate, bellatrix's an execution payload,
        // and so on), but `process_block_header` reads only the four
        // fork-invariant fields below, so decoding with the fork's own type
        // and then handing those four fields to one shared function is all
        // this needs; see this module's own documentation.
        "block_header" => match case.fork {
            ForkName::Phase0 => {
                let block: phase0::BeaconBlock = case.ssz("block");
                block::process_block_header(
                    state,
                    block.slot,
                    block.proposer_index,
                    block.parent_root,
                    block.body.hash_tree_root(),
                )
            }
            ForkName::Altair => {
                let block: altair::BeaconBlock = case.ssz("block");
                block::process_block_header(
                    state,
                    block.slot,
                    block.proposer_index,
                    block.parent_root,
                    block.body.hash_tree_root(),
                )
            }
            ForkName::Bellatrix => {
                let block: bellatrix::BeaconBlock = case.ssz("block");
                block::process_block_header(
                    state,
                    block.slot,
                    block.proposer_index,
                    block.parent_root,
                    block.body.hash_tree_root(),
                )
            }
            ForkName::Capella => {
                let block: capella::BeaconBlock = case.ssz("block");
                block::process_block_header(
                    state,
                    block.slot,
                    block.proposer_index,
                    block.parent_root,
                    block.body.hash_tree_root(),
                )
            }
            ForkName::Deneb => {
                let block: deneb::BeaconBlock = case.ssz("block");
                block::process_block_header(
                    state,
                    block.slot,
                    block.proposer_index,
                    block.parent_root,
                    block.body.hash_tree_root(),
                )
            }
            // Electra and fulu share one `BeaconBlock`: fulu's specification
            // changes nothing about the block or body shape, only
            // `process_execution_payload` (see the `execution_payload` arm
            // below), so there is no `fulu::BeaconBlock` to decode.
            ForkName::Electra | ForkName::Fulu => {
                let block: electra::BeaconBlock = case.ssz("block");
                block::process_block_header(
                    state,
                    block.slot,
                    block.proposer_index,
                    block.parent_root,
                    block.body.hash_tree_root(),
                )
            }
            ForkName::Gloas => Err(
                ethlambda_state_transition::beacon::Error::UnsupportedForFork {
                    function: "block_header",
                    fork: ForkName::Gloas,
                },
            ),
            // No `other` arm: the patterns above already cover every `ForkName`
            // there is, so a catch-all here would be dead code rather than a
            // safety net. `Lean` is covered by name for the same reason, rather
            // than swept into one; see `lean_is_not_a_fixture_fork`.
            ForkName::Lean => lean_is_not_a_fixture_fork("block_header"),
        },
        "attestation" => match case.fork {
            // Phase0 defers every attestation's reward to the epoch boundary.
            ForkName::Phase0 => {
                let attestation: phase0::Attestation = case.ssz("attestation");
                operations::process_attestation(state, &attestation, config, &committees)
            }
            // Altair scores an attestation immediately instead, and neither
            // bellatrix's nor capella's specification lists a further change,
            // so altair's own function serves both.
            ForkName::Altair | ForkName::Bellatrix | ForkName::Capella => {
                let attestation: phase0::Attestation = case.ssz("attestation");
                altair_stf::process_attestation(state, &attestation, &committees)
            }
            // Deneb widens the inclusion window and the timely-target
            // condition (EIP-7045); the container is still phase0's.
            ForkName::Deneb => {
                let attestation: phase0::Attestation = case.ssz("attestation");
                deneb_stf::process_attestation(state, &attestation, &committees)
            }
            // Electra reshapes the container itself (EIP-7549's
            // `committee_bits`), and fulu's specification makes no further
            // change to either the container or the function.
            ForkName::Electra | ForkName::Fulu => {
                let attestation: electra::Attestation = case.ssz("attestation");
                electra_stf::process_attestation(state, &attestation, &committees)
            }
            ForkName::Gloas => Err(
                ethlambda_state_transition::beacon::Error::UnsupportedForFork {
                    function: "attestation",
                    fork: ForkName::Gloas,
                },
            ),
            ForkName::Lean => lean_is_not_a_fixture_fork("attestation"),
        },
        "attester_slashing" => match case.fork {
            // Unchanged from phase0 through deneb, container included.
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb => {
                let slashing: phase0::AttesterSlashing = case.ssz("attester_slashing");
                operations::process_attester_slashing(state, &slashing, config)
            }
            // Electra's container widens the same way `Attestation`'s does
            // (see the `attestation` arm above); the function itself is not
            // behaviorally modified, only transcribed against the new type.
            // Fulu's specification changes neither.
            ForkName::Electra | ForkName::Fulu => {
                let slashing: electra::AttesterSlashing = case.ssz("attester_slashing");
                electra_stf::process_attester_slashing(state, &slashing, config)
            }
            ForkName::Gloas => Err(
                ethlambda_state_transition::beacon::Error::UnsupportedForFork {
                    function: "attester_slashing",
                    fork: ForkName::Gloas,
                },
            ),
            ForkName::Lean => lean_is_not_a_fixture_fork("attester_slashing"),
        },
        // `ProposerSlashing` never changes shape, and no fork's specification
        // ever lists a modified `process_proposer_slashing`, so this needs no
        // per-fork routing at all.
        "proposer_slashing" => {
            let slashing: shared::ProposerSlashing = case.ssz("proposer_slashing");
            operations::process_proposer_slashing(state, &slashing, config)
        }
        "deposit" => match case.fork {
            // The `Deposit` container never changes shape; through deneb a
            // deposit's amount is credited the moment it is processed.
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb => {
                let deposit: shared::Deposit = case.ssz("deposit");
                operations::process_deposit(state, &deposit, config)
            }
            // Electra queues a deposit's amount instead of crediting it
            // directly (EIP-7251), so the epoch boundary can rate-limit
            // activation by balance rather than by validator count. Fulu's
            // specification removes `process_deposit` outright rather than
            // modifying it (`beacon-chain.md`'s "Modified `process_operations`":
            // `assert len(body.deposits) == 0`, no call at all), so this
            // fulu arm is dead in practice: beta.2 ships no fulu
            // `operations/deposit` fixtures. Kept rather than dropped so a
            // future fixture release that does ship one fails loudly through
            // whatever electra's function rejects it for, not silently
            // through `unhandled operation`.
            ForkName::Electra | ForkName::Fulu => {
                let deposit: shared::Deposit = case.ssz("deposit");
                electra_stf::process_deposit(state, &deposit, config)
            }
            ForkName::Gloas => Err(
                ethlambda_state_transition::beacon::Error::UnsupportedForFork {
                    function: "deposit",
                    fork: ForkName::Gloas,
                },
            ),
            ForkName::Lean => lean_is_not_a_fixture_fork("deposit"),
        },
        "voluntary_exit" => match case.fork {
            // Unchanged through capella.
            ForkName::Phase0 | ForkName::Altair | ForkName::Bellatrix | ForkName::Capella => {
                let exit: shared::SignedVoluntaryExit = case.ssz("voluntary_exit");
                operations::process_voluntary_exit(state, &exit, config)
            }
            // Deneb pins the signature to `CAPELLA_FORK_VERSION` (EIP-7044),
            // so an exit signed long before it takes effect never expires
            // out from under its own signer at a later fork boundary.
            ForkName::Deneb => {
                let exit: shared::SignedVoluntaryExit = case.ssz("voluntary_exit");
                deneb_stf::process_voluntary_exit(state, &exit, config)
            }
            // Electra adds a pending-partial-withdrawal check and its own
            // balance-churn exit-queue accounting (EIP-7251); fulu's
            // specification changes neither.
            ForkName::Electra | ForkName::Fulu => {
                let exit: shared::SignedVoluntaryExit = case.ssz("voluntary_exit");
                electra_stf::process_voluntary_exit(state, &exit, config)
            }
            ForkName::Gloas => Err(
                ethlambda_state_transition::beacon::Error::UnsupportedForFork {
                    function: "voluntary_exit",
                    fork: ForkName::Gloas,
                },
            ),
            ForkName::Lean => lean_is_not_a_fixture_fork("voluntary_exit"),
        },
        // New in altair, and never listed as modified again, so this needs no
        // further fork match.
        "sync_aggregate" => {
            let sync_aggregate: altair::SyncAggregate = case.ssz("sync_aggregate");
            altair_stf::process_sync_aggregate(state, &sync_aggregate)
        }
        // The fixture's operation file is a whole `BeaconBlockBody`, not a
        // bare payload: checking one needs fields that live on the body
        // alongside it (deneb's and later's blob commitments), not on the
        // payload itself. See this module's own documentation for why every
        // fork from bellatrix on gets its own arm here.
        "execution_payload" => {
            let execution: ExecutionYaml = case.yaml("execution");
            let engine = ExecutionEngine {
                execution_valid: execution.execution_valid,
            };
            match case.fork {
                ForkName::Bellatrix => {
                    let body: bellatrix::BeaconBlockBody = case.ssz("body");
                    bellatrix_stf::process_execution_payload(
                        state,
                        &body.execution_payload,
                        config,
                        &engine,
                    )
                }
                // Capella's specification drops the still-mid-merge-transition
                // check bellatrix's version makes, on the grounds that no
                // chain reaching capella can still be pre-merge.
                ForkName::Capella => {
                    let body: capella::BeaconBlockBody = case.ssz("body");
                    capella_stf::process_execution_payload(
                        state,
                        &body.execution_payload,
                        config,
                        &engine,
                    )
                }
                // Deneb adds the blob commitment count check (EIP-4844),
                // which reads the body's own `blob_kzg_commitments` rather
                // than anything on the payload.
                ForkName::Deneb => {
                    let body: deneb::BeaconBlockBody = case.ssz("body");
                    deneb_stf::process_execution_payload(
                        state,
                        &body.execution_payload,
                        &body.blob_kzg_commitments,
                        config,
                        &engine,
                    )
                }
                // Electra reads a configuration field of its own for that
                // same count (EIP-7691) rather than deneb's fixed one, so it
                // is not deneb's function under a new name; both take the
                // whole body directly instead of a payload and a commitment
                // list separately.
                ForkName::Electra => {
                    let body: electra::BeaconBlockBody = case.ssz("body");
                    electra_stf::process_execution_payload(state, &body, config, &engine)
                }
                // Fulu reads a schedule-aware limit instead of electra's
                // fixed configuration field (EIP-7892), and carries no
                // `BeaconBlockBody` of its own to decode, since fulu changes
                // nothing else about the block or body shape.
                ForkName::Fulu => {
                    let body: electra::BeaconBlockBody = case.ssz("body");
                    fulu_stf::process_execution_payload(state, &body, config, &engine)
                }
                fork @ (ForkName::Phase0 | ForkName::Altair) => {
                    return Err(format!(
                        "execution_payload has no handler for fork `{fork}`"
                    ));
                }
                ForkName::Gloas => Err(
                    ethlambda_state_transition::beacon::Error::UnsupportedForFork {
                        function: "execution_payload",
                        fork: ForkName::Gloas,
                    },
                ),
                ForkName::Lean => lean_is_not_a_fixture_fork("execution_payload"),
            }
        }
        // New in capella, named `address_change` in the fixture tree even
        // though the handler is `bls_to_execution_change`. Reads and writes
        // only fork-invariant fields (the validator registry and the
        // genesis validators root), and no later fork's specification lists
        // a modified version, so capella's own function serves every fork
        // from here on.
        "bls_to_execution_change" => {
            let signed_change: capella::SignedBLSToExecutionChange = case.ssz("address_change");
            capella_stf::process_bls_to_execution_change(state, &signed_change, config)
        }
        "withdrawals" => match case.fork {
            ForkName::Capella => {
                let payload: capella::ExecutionPayload = case.ssz("execution_payload");
                capella_stf::process_withdrawals(state, &payload)
            }
            // Deneb's own specification lists no modified `process_withdrawals`
            // at all: this is identical to capella's beyond the type of
            // `payload` it takes, since `payload.withdrawals` has to compare
            // against a `deneb::ExecutionPayload`, a different Rust type from
            // `capella::ExecutionPayload` even though both alias the same
            // element type for the list itself.
            ForkName::Deneb => {
                let payload: deneb::ExecutionPayload = case.ssz("execution_payload");
                deneb_stf::process_withdrawals(state, &payload)
            }
            // Electra adds the partial-withdrawal queue sweep (EIP-7251);
            // fulu's specification changes nothing further, and both share
            // deneb's `ExecutionPayload` type for the `payload` parameter,
            // the same reuse `execution_payload`'s electra arm above relies
            // on.
            ForkName::Electra | ForkName::Fulu => {
                let payload: deneb::ExecutionPayload = case.ssz("execution_payload");
                electra_stf::process_withdrawals(state, &payload)
            }
            fork @ (ForkName::Phase0 | ForkName::Altair | ForkName::Bellatrix) => {
                return Err(format!("withdrawals has no handler for fork `{fork}`"));
            }
            // Modified again at gloas (EIP-7732): `process_withdrawals` drops
            // its `payload` parameter entirely, since withdrawals are now
            // deterministic from the state alone. This is the one fork whose
            // arm reads no operation file at all.
            ForkName::Gloas => gloas_stf::process_withdrawals(state),
            ForkName::Lean => lean_is_not_a_fixture_fork("withdrawals"),
        },
        // New in gloas (EIP-7732): the block's binding commitment to a
        // builder's payload.
        "execution_payload_bid" => {
            let signed_bid: gloas::SignedExecutionPayloadBid = case.ssz("execution_payload_bid");
            gloas_stf::process_execution_payload_bid(state, &signed_bid, config)
        }
        // New in gloas (EIP-7732): the *next* block's processing of the
        // previous slot's payload, so the fixture's operation file is a whole
        // `BeaconBlock`, named `block` like `block_header`'s.
        "parent_execution_payload" => {
            let block: gloas::BeaconBlock = case.ssz("block");
            gloas_stf::process_parent_execution_payload(state, &block, config)
        }
        // `consolidation_request` and `withdrawal_request` are new in
        // electra, alongside `withdrawals`; neither fulu's nor gloas's own
        // specification lists either as modified (gloas's own
        // `apply_parent_execution_payload` is the only caller left once
        // `process_operations` drops the call, but the function itself is
        // unchanged), so electra's own functions serve every later fork's
        // cases too. `ConsolidationRequest` and `WithdrawalRequest` are
        // likewise electra's own containers, reused unchanged, so no fork
        // match is needed for either the type or the call.
        "consolidation_request" => {
            let request: electra::ConsolidationRequest = case.ssz("consolidation_request");
            electra_stf::process_consolidation_request(state, &request, config)
        }
        // `deposit_request` is new in electra too, but fulu's specification
        // does list a modified version (`beacon-chain.md`'s "Modified
        // `process_deposit_request`"): it drops the statement that sets
        // `deposit_requests_start_index` the first time a request is seen,
        // since fulu retires the eth1-bridge deposit mechanism outright (see
        // `fulu_stf::process_deposit_request`'s own doc). Gloas's own
        // specification does not redefine the function again, so it inherits
        // fulu's version rather than electra's, the same way gloas's own
        // `apply_parent_execution_payload` calls straight into
        // `fulu_stf::process_deposit_request`. Routing a fulu or gloas case to
        // electra's version regardless would still pass every fixture shipped
        // so far, since pyspec's own genesis for both already sets that
        // field, but it is not the function either fork's specification names.
        "deposit_request" => match case.fork {
            ForkName::Fulu | ForkName::Gloas => {
                let request: electra::DepositRequest = case.ssz("deposit_request");
                fulu_stf::process_deposit_request(state, &request)
            }
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra => {
                let request: electra::DepositRequest = case.ssz("deposit_request");
                electra_stf::process_deposit_request(state, &request)
            }
            ForkName::Lean => lean_is_not_a_fixture_fork("deposit_request"),
        },
        "withdrawal_request" => {
            let request: electra::WithdrawalRequest = case.ssz("withdrawal_request");
            electra_stf::process_withdrawal_request(state, &request, config)
        }
        // New in gloas (EIP-8282): the builder registry's own onboarding and
        // exit requests, applied by `apply_parent_execution_payload` the same
        // way the validator registry's own deposit/withdrawal/consolidation
        // requests are.
        "builder_deposit_request" => {
            let request: gloas::BuilderDepositRequest = case.ssz("builder_deposit_request");
            gloas_stf::process_builder_deposit_request(state, &request, config)
        }
        "builder_exit_request" => {
            let request: gloas::BuilderExitRequest = case.ssz("builder_exit_request");
            gloas_stf::process_builder_exit_request(state, &request, config)
        }
        other => return Err(format!("unhandled operation `{other}`")),
    };

    outcome.map_err(|err| format!("{err:?}"))
}

pub fn trials() -> Vec<Trial> {
    let config = Arc::new(Config::active());
    let cases = collect_all_handlers(PRESET, "operations");
    let mut trials = vec![super::discovery_trial("operations", cases.len())];

    for (handler, case) in cases {
        let config = Arc::clone(&config);
        trials.push(super::case_trial("operations", case, move |case| {
            let mut state = BeaconState::from_ssz(case.fork, &case.ssz_bytes("pre"))
                .map_err(|err| format!("the fixture's pre-state does not decode: {err:?}"))?;

            let outcome = apply(&handler, case, &mut state, &config);
            super::check_transition(case, outcome, &state)
        }));
    }

    trials.push(Trial::test(
        "operations/every_shipped_handler_is_dispatched",
        every_shipped_handler_is_dispatched,
    ));

    trials
}

/// Handlers the fixture release ships that this runner does not dispatch.
///
/// A missing arm in [`apply`] would otherwise be reported per case as a
/// failure, which is correct but noisy. This asserts the set of handlers is
/// the one the runner knows about, so a fixture release that adds an
/// operation fails here, once, with a clear message. The list is flat across
/// forks (it does not say which handler belongs to which fork) because that
/// is exactly what [`apply`]'s per-handler, per-fork match already encodes
/// and enforces at run time; duplicating it here would only give the two a
/// chance to drift apart.
fn every_shipped_handler_is_dispatched() -> Result<(), Failed> {
    let known = [
        "attestation",
        "attester_slashing",
        "block_header",
        "bls_to_execution_change",
        "builder_deposit_request",
        "builder_exit_request",
        "consolidation_request",
        "deposit",
        "deposit_request",
        "execution_payload",
        "execution_payload_bid",
        "parent_execution_payload",
        "proposer_slashing",
        "sync_aggregate",
        "voluntary_exit",
        "withdrawal_request",
        "withdrawals",
    ];

    let mut unknown: Vec<String> = collect_all_handlers(PRESET, "operations")
        .into_iter()
        .filter(|(_, case): &(String, Case)| case.in_scope())
        .map(|(handler, _)| handler)
        .filter(|handler| !known.contains(&handler.as_str()))
        .collect();
    unknown.sort_unstable();
    unknown.dedup();

    if !unknown.is_empty() {
        return Err(Failed::from(format!(
            "the fixture release ships operations this runner does not dispatch: {unknown:?}"
        )));
    }

    Ok(())
}
