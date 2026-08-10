//! The `kzg` runner.
//!
//! Covers every function `crates/beacon/src/kzg.rs` wraps from `c-kzg`: deneb's
//! seven blob-commitment handlers (`blob_to_kzg_commitment`,
//! `compute_kzg_proof`, `compute_blob_kzg_proof`, `verify_kzg_proof`,
//! `verify_blob_kzg_proof`, `verify_blob_kzg_proof_batch`, `compute_challenge`)
//! and fulu's five cell-proof handlers for PeerDAS
//! (`compute_cells`, `compute_cells_and_kzg_proofs`,
//! `recover_cells_and_kzg_proofs`, `verify_cell_kzg_proof_batch`,
//! `compute_verify_cell_kzg_proof_batch_challenge`). Before this runner, no
//! fixture exercised any of them outside `kzg.rs`'s own ad hoc test module,
//! which predates this crate's shared fixture harness and is not wired into
//! `spec_tests` or its per-case reporting.
//!
//! # Why `general`, not a preset
//!
//! [`super::PRESET`] selects between `minimal` and `mainnet` because container
//! bounds like `SLOTS_PER_EPOCH` are compiled in. Nothing about a blob, a cell,
//! or a KZG point is preset-dependent in that sense: `BYTES_PER_BLOB`,
//! `CELLS_PER_EXT_BLOB`, and the rest come from the KZG trusted setup and the
//! EIP-4844/EIP-7594 scheme itself, which is one fixed size regardless of which
//! preset the beacon state around it uses. So the release ships exactly one
//! `kzg` tree per fork, under `general`, the same reason [`super::collect_all_handlers`]'s
//! own doc gives for BLS.
//!
//! # What `output: null` means
//!
//! A case whose `output` is `null` means the operation must be rejected, the
//! same rule [`super::check_transition`] enforces elsewhere in this harness for
//! a case with no `post` state. The two look different only because a state
//! transition case expresses "no expected result" by omitting a file, while a
//! KZG case has no state to omit and expresses it with YAML's null instead. A
//! run that returns a value for such a case has to fail, not pass by
//! coincidence: the KZG suite spends a large share of its cases on malformed
//! input precisely because acceptance is easy to get right by accident and
//! rejection is not, so that half of the suite is where most of its value is.
//!
//! Some of this crate's KZG functions cannot even be called on a case that
//! must be rejected, rather than being called and returning `Err`: a case
//! whose `z`, `y`, `commitment`, `proof`, or `cell` field is not the exact byte
//! length its typed argument requires ([`Bytes32`], [`KzgCommitment`],
//! [`KzgProof`], [`Cell`]) fails before this runner can construct the value to
//! pass in. [`expect_rejected`] covers both paths with one check, since the
//! fixture's contract is the same either way: `output` must be `null`.
//!
//! # Why dispatch is on the handler alone
//!
//! [`super::ssz_static`] and [`super::epoch_processing`] match on
//! `(handler, fork)`, because the same handler name can select a different
//! function per fork there (`rewards_and_penalties` is phase0's replaying
//! `PendingAttestation`s versus altair's scoring participation flags, for
//! instance). Nothing here has that shape: deneb's seven handlers and fulu's
//! five are two disjoint sets, no name appears in both, and neither fork's
//! `polynomial-commitments*.md` redefines a function the other fork also
//! defines. So [`run`] matches on the handler name by itself; adding the fork
//! to the match would be dead weight, not a safety net, since no arm could
//! ever need it.

use c_kzg::Cell;
use ethlambda_beacon::kzg;
use ethlambda_beacon::primitives::{Bytes32, H256, KzgCommitment, KzgProof};
use libtest_mimic::Trial;
use serde_yaml_ng::Value;

use super::{Case, collect_all_handlers};

/// Decodes a `0x`-prefixed hex string into bytes of whatever length it has.
///
/// This is how a blob is decoded: its typed argument is `&[u8]`, not a fixed
/// array, so [`kzg`]'s own length check (`to_blob`, inside every function that
/// takes one) is what rejects a case whose blob is the wrong length, not this
/// runner. Every fixed-size field below builds on this, then narrows further.
fn hex_bytes(value: &Value) -> Vec<u8> {
    let hex_str = value.as_str().expect("value is a hex string");
    hex::decode(
        hex_str
            .strip_prefix("0x")
            .expect("hex string has a 0x prefix"),
    )
    .expect("value is valid hex")
}

/// Decodes a hex string into exactly `N` bytes, or `None` if its length does
/// not match.
///
/// `N` is not a spec constant, only the width one of this module's own byte
/// arrays needs, so nothing here reaches for a name; the constant that does
/// matter, e.g. `BYTES_PER_CELL`, only lives inside `c-kzg` and this module
/// never repeats its value.
fn hex_array<const N: usize>(value: &Value) -> Option<[u8; N]> {
    hex_bytes(value).try_into().ok()
}

/// Decodes a 32-byte field element (`z`, `y`, or a coset evaluation).
fn hex_bytes32(value: &Value) -> Option<Bytes32> {
    hex_array::<32>(value).map(H256)
}

/// Decodes a compressed G1 point as a commitment.
fn hex_commitment(value: &Value) -> Option<KzgCommitment> {
    hex_array(value).map(KzgCommitment)
}

/// Decodes a compressed G1 point as a proof.
fn hex_proof(value: &Value) -> Option<KzgProof> {
    hex_array(value).map(KzgProof)
}

/// Decodes one cell of an extended blob.
///
/// Unlike the fixed arrays above, [`Cell::from_bytes`] does its own length
/// check rather than this runner doing it through `try_into`, since `Cell` is
/// `c-kzg`'s type, not this crate's; `None` on a length mismatch either way.
fn hex_cell(value: &Value) -> Option<Cell> {
    Cell::from_bytes(&hex_bytes(value)).ok()
}

/// Parses a YAML list of plain integers (`cell_indices`, `commitment_indices`),
/// as opposed to the hex-string lists every other list field in this suite
/// holds.
fn u64_list(value: &Value) -> Vec<u64> {
    value
        .as_sequence()
        .expect("value is a list")
        .iter()
        .map(|entry| entry.as_u64().expect("list entry is an integer"))
        .collect()
}

/// Parses every element of a YAML list with `parse`, unconditionally.
///
/// For fields whose own function call rejects a bad element instead of this
/// runner needing to notice first, e.g. blobs in a batch: `kzg`'s own
/// per-blob length check runs inside the call itself, not here.
fn hex_list<T>(value: &Value, parse: impl Fn(&Value) -> T) -> Vec<T> {
    value
        .as_sequence()
        .expect("value is a list")
        .iter()
        .map(parse)
        .collect()
}

/// Parses every element of a YAML list with a fallible `parse`, or `None` if
/// any element fails.
///
/// For fields whose typed element (a commitment, a proof, a cell) this runner
/// must construct itself before it can even call the function under test, so
/// one malformed element has to short-circuit the whole case to a rejection
/// before that call happens.
fn hex_list_opt<T>(value: &Value, parse: impl Fn(&Value) -> Option<T>) -> Option<Vec<T>> {
    value
        .as_sequence()
        .expect("value is a list")
        .iter()
        .map(parse)
        .collect()
}

/// Checks that `actual` equals `expected`, formatting either mismatch.
fn expect_eq<T: PartialEq + std::fmt::Debug>(actual: T, expected: T) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{actual:?} != {expected:?}"))
    }
}

/// Checks that `output` is `null`, the fixture's way of demanding a rejection.
///
/// `reason` names why this case could not produce a value: either an input
/// field failed to parse at its required fixed size, before this crate's KZG
/// function could even be called, or that function itself returned `Err`. See
/// the module doc for why both collapse to the same check.
fn expect_rejected(output: &Value, reason: &str) -> Result<(), String> {
    if output.is_null() {
        Ok(())
    } else {
        Err(format!(
            "rejected ({reason}), but the fixture expects output {output:?}"
        ))
    }
}

/// Checks a list of cells against the fixture's own list, element by element.
fn expect_cells_eq(actual: &[Cell], expected: &[Value]) -> Result<(), String> {
    if actual.len() != expected.len() {
        return Err(format!(
            "produced {} cells, fixture expects {}",
            actual.len(),
            expected.len()
        ));
    }
    for (cell, expected_cell) in actual.iter().zip(expected) {
        expect_eq(Some(*cell), hex_cell(expected_cell))?;
    }
    Ok(())
}

/// Checks a list of proofs against the fixture's own list, element by element.
fn expect_proofs_eq(actual: &[KzgProof], expected: &[Value]) -> Result<(), String> {
    if actual.len() != expected.len() {
        return Err(format!(
            "produced {} proofs, fixture expects {}",
            actual.len(),
            expected.len()
        ));
    }
    for (proof, expected_proof) in actual.iter().zip(expected) {
        expect_eq(Some(*proof), hex_proof(expected_proof))?;
    }
    Ok(())
}

fn check_blob_to_kzg_commitment(input: &Value, output: &Value) -> Result<(), String> {
    let blob = hex_bytes(&input["blob"]);
    match kzg::blob_to_kzg_commitment(&blob) {
        Ok(commitment) => expect_eq(Some(commitment), hex_commitment(output)),
        Err(err) => expect_rejected(output, &format!("{err:?}")),
    }
}

fn check_compute_kzg_proof(input: &Value, output: &Value) -> Result<(), String> {
    let blob = hex_bytes(&input["blob"]);
    let Some(z) = hex_bytes32(&input["z"]) else {
        return expect_rejected(output, "z is not 32 bytes");
    };
    match kzg::compute_kzg_proof(&blob, &z) {
        Ok((proof, y)) => {
            let expected = output
                .as_sequence()
                .ok_or_else(|| format!("output {output:?} is not [proof, y]"))?;
            expect_eq(Some(proof), hex_proof(&expected[0]))?;
            expect_eq(Some(y), hex_bytes32(&expected[1]))
        }
        Err(err) => expect_rejected(output, &format!("{err:?}")),
    }
}

fn check_compute_blob_kzg_proof(input: &Value, output: &Value) -> Result<(), String> {
    let blob = hex_bytes(&input["blob"]);
    let Some(commitment) = hex_commitment(&input["commitment"]) else {
        return expect_rejected(output, "commitment is not 48 bytes");
    };
    match kzg::compute_blob_kzg_proof(&blob, &commitment) {
        Ok(proof) => expect_eq(Some(proof), hex_proof(output)),
        Err(err) => expect_rejected(output, &format!("{err:?}")),
    }
}

fn check_verify_kzg_proof(input: &Value, output: &Value) -> Result<(), String> {
    let (Some(commitment), Some(z), Some(y), Some(proof)) = (
        hex_commitment(&input["commitment"]),
        hex_bytes32(&input["z"]),
        hex_bytes32(&input["y"]),
        hex_proof(&input["proof"]),
    ) else {
        return expect_rejected(output, "commitment, z, y, or proof is the wrong length");
    };
    match kzg::verify_kzg_proof(&commitment, &z, &y, &proof) {
        Ok(verified) => expect_eq(Some(verified), output.as_bool()),
        Err(err) => expect_rejected(output, &format!("{err:?}")),
    }
}

fn check_verify_blob_kzg_proof(input: &Value, output: &Value) -> Result<(), String> {
    let blob = hex_bytes(&input["blob"]);
    let (Some(commitment), Some(proof)) = (
        hex_commitment(&input["commitment"]),
        hex_proof(&input["proof"]),
    ) else {
        return expect_rejected(output, "commitment or proof is the wrong length");
    };
    match kzg::verify_blob_kzg_proof(&blob, &commitment, &proof) {
        Ok(verified) => expect_eq(Some(verified), output.as_bool()),
        Err(err) => expect_rejected(output, &format!("{err:?}")),
    }
}

fn check_verify_blob_kzg_proof_batch(input: &Value, output: &Value) -> Result<(), String> {
    // Blobs are decoded unconditionally, unlike commitments and proofs below:
    // a batch member's own length check happens inside `verify_blob_kzg_proof_batch`
    // itself (`to_blob`, per element), not here.
    let blobs = hex_list(&input["blobs"], hex_bytes);
    let blob_refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
    let (Some(commitments), Some(proofs)) = (
        hex_list_opt(&input["commitments"], hex_commitment),
        hex_list_opt(&input["proofs"], hex_proof),
    ) else {
        return expect_rejected(output, "a commitment or proof is the wrong length");
    };
    match kzg::verify_blob_kzg_proof_batch(&blob_refs, &commitments, &proofs) {
        Ok(verified) => expect_eq(Some(verified), output.as_bool()),
        Err(err) => expect_rejected(output, &format!("{err:?}")),
    }
}

/// `compute_challenge`'s fixtures carry no `output: null` case: unlike every
/// handler above, hashing a Fiat-Shamir transcript never fails on the
/// *content* of `blob` or `commitment`, only on `blob`'s length, which
/// [`kzg::compute_challenge`] itself checks (see its own doc). The `Err` arm
/// stays here anyway, matching every other handler, so a future fixture that
/// does exercise that length check is still handled rather than silently
/// mismatching the return type.
fn check_compute_challenge(input: &Value, output: &Value) -> Result<(), String> {
    let blob = hex_bytes(&input["blob"]);
    let Some(commitment) = hex_commitment(&input["commitment"]) else {
        return expect_rejected(output, "commitment is not 48 bytes");
    };
    match kzg::compute_challenge(&blob, &commitment) {
        Ok(challenge) => expect_eq(Some(challenge), hex_bytes32(output)),
        Err(err) => expect_rejected(output, &format!("{err:?}")),
    }
}

fn check_compute_cells(input: &Value, output: &Value) -> Result<(), String> {
    let blob = hex_bytes(&input["blob"]);
    match kzg::compute_cells(&blob) {
        Ok(cells) => {
            let expected = output
                .as_sequence()
                .ok_or_else(|| format!("output {output:?} is not a list of cells"))?;
            expect_cells_eq(cells.as_ref(), expected)
        }
        Err(err) => expect_rejected(output, &format!("{err:?}")),
    }
}

fn check_compute_cells_and_kzg_proofs(input: &Value, output: &Value) -> Result<(), String> {
    let blob = hex_bytes(&input["blob"]);
    match kzg::compute_cells_and_kzg_proofs(&blob) {
        Ok((cells, proofs)) => {
            let expected = output
                .as_sequence()
                .ok_or_else(|| format!("output {output:?} is not [cells, proofs]"))?;
            let expected_cells = expected[0]
                .as_sequence()
                .ok_or_else(|| "cells is not a list".to_string())?;
            let expected_proofs = expected[1]
                .as_sequence()
                .ok_or_else(|| "proofs is not a list".to_string())?;
            expect_cells_eq(cells.as_ref(), expected_cells)?;
            expect_proofs_eq(proofs.as_ref(), expected_proofs)
        }
        Err(err) => expect_rejected(output, &format!("{err:?}")),
    }
}

fn check_recover_cells_and_kzg_proofs(input: &Value, output: &Value) -> Result<(), String> {
    let cell_indices = u64_list(&input["cell_indices"]);
    let Some(cells) = hex_list_opt(&input["cells"], hex_cell) else {
        return expect_rejected(output, "a cell is the wrong length");
    };
    match kzg::recover_cells_and_kzg_proofs(&cell_indices, &cells) {
        Ok((recovered_cells, recovered_proofs)) => {
            let expected = output
                .as_sequence()
                .ok_or_else(|| format!("output {output:?} is not [cells, proofs]"))?;
            let expected_cells = expected[0]
                .as_sequence()
                .ok_or_else(|| "cells is not a list".to_string())?;
            let expected_proofs = expected[1]
                .as_sequence()
                .ok_or_else(|| "proofs is not a list".to_string())?;
            expect_cells_eq(recovered_cells.as_ref(), expected_cells)?;
            expect_proofs_eq(recovered_proofs.as_ref(), expected_proofs)
        }
        Err(err) => expect_rejected(output, &format!("{err:?}")),
    }
}

fn check_verify_cell_kzg_proof_batch(input: &Value, output: &Value) -> Result<(), String> {
    // A length mismatch *between* the four arrays (some `invalid_missing_*`
    // cases supply fewer cells than cell_indices, for instance) is not caught
    // here: every element still decodes at its own correct size, so
    // `hex_list_opt` succeeds, and it is `verify_cell_kzg_proof_batch` itself
    // that rejects the mismatched lengths (see its own doc).
    let cell_indices = u64_list(&input["cell_indices"]);
    let (Some(commitments), Some(cells), Some(proofs)) = (
        hex_list_opt(&input["commitments"], hex_commitment),
        hex_list_opt(&input["cells"], hex_cell),
        hex_list_opt(&input["proofs"], hex_proof),
    ) else {
        return expect_rejected(output, "a commitment, cell, or proof is the wrong length");
    };
    match kzg::verify_cell_kzg_proof_batch(&commitments, &cell_indices, &cells, &proofs) {
        Ok(verified) => expect_eq(Some(verified), output.as_bool()),
        Err(err) => expect_rejected(output, &format!("{err:?}")),
    }
}

/// Like `compute_challenge`, this fixture set carries no `output: null` case,
/// for the same reason: the transcript is raw bytes and indices, hashed, with
/// no curve-point validation along the way. What it can still fail on is the
/// array-length agreement [`kzg::compute_verify_cell_kzg_proof_batch_challenge`]
/// checks itself (`commitment_indices`, `cell_indices`, and `proofs` one entry
/// per coset), so the `Err` arm is kept for the same forward-compatibility
/// reason `check_compute_challenge` keeps its own.
fn check_compute_verify_cell_kzg_proof_batch_challenge(
    input: &Value,
    output: &Value,
) -> Result<(), String> {
    let commitment_indices = u64_list(&input["commitment_indices"]);
    let cell_indices = u64_list(&input["cell_indices"]);
    let (Some(commitments), Some(cosets_evals), Some(proofs)) = (
        hex_list_opt(&input["commitments"], hex_commitment),
        hex_list_opt(&input["cosets_evals"], |coset| {
            hex_list_opt(coset, hex_bytes32)
        }),
        hex_list_opt(&input["proofs"], hex_proof),
    ) else {
        return expect_rejected(
            output,
            "a commitment, coset evaluation, or proof is the wrong length",
        );
    };
    match kzg::compute_verify_cell_kzg_proof_batch_challenge(
        &commitments,
        &commitment_indices,
        &cell_indices,
        &cosets_evals,
        &proofs,
    ) {
        Ok(challenge) => expect_eq(Some(challenge), hex_bytes32(output)),
        Err(err) => expect_rejected(output, &format!("{err:?}")),
    }
}

/// Dispatches one case to the check function its handler names.
///
/// See the module doc for why this matches on `handler` alone rather than on
/// `(handler, fork)`.
fn run(handler: &str, case: &Case) -> Result<(), String> {
    let data: Value = case.yaml("data");
    let input = &data["input"];
    let output = &data["output"];

    match handler {
        "blob_to_kzg_commitment" => check_blob_to_kzg_commitment(input, output),
        "compute_kzg_proof" => check_compute_kzg_proof(input, output),
        "compute_blob_kzg_proof" => check_compute_blob_kzg_proof(input, output),
        "verify_kzg_proof" => check_verify_kzg_proof(input, output),
        "verify_blob_kzg_proof" => check_verify_blob_kzg_proof(input, output),
        "verify_blob_kzg_proof_batch" => check_verify_blob_kzg_proof_batch(input, output),
        "compute_challenge" => check_compute_challenge(input, output),
        "compute_cells" => check_compute_cells(input, output),
        "compute_cells_and_kzg_proofs" => check_compute_cells_and_kzg_proofs(input, output),
        "recover_cells_and_kzg_proofs" => check_recover_cells_and_kzg_proofs(input, output),
        "verify_cell_kzg_proof_batch" => check_verify_cell_kzg_proof_batch(input, output),
        "compute_verify_cell_kzg_proof_batch_challenge" => {
            check_compute_verify_cell_kzg_proof_batch_challenge(input, output)
        }
        // A fixture release that adds a thirteenth handler must fail loudly
        // here rather than pass by never being dispatched: an unmatched
        // handler has no check function to fall back on, unlike a fork this
        // crate has not implemented yet, which `case_trial` marks ignored
        // instead of failed.
        other => Err(format!("unhandled kzg handler `{other}`")),
    }
}

pub fn trials() -> Vec<Trial> {
    let cases = collect_all_handlers("general", "kzg");
    let mut trials = vec![super::discovery_trial("kzg", cases.len())];

    for (handler, case) in cases {
        trials.push(super::case_trial("kzg", case, move |case| {
            run(&handler, case)
        }));
    }

    trials
}
