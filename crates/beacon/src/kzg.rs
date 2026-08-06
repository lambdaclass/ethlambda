//! KZG polynomial commitments: EIP-4844 blobs (deneb) and their EIP-7594 cell
//! proofs (fulu).
//!
//! This module wraps [`c-kzg`](https://github.com/ethereum/c-kzg-4844), the C
//! library the specification's own polynomial-commitments documents describe,
//! and exposes it under the specification's own function names so call sites
//! read like `specs/deneb/polynomial-commitments.md` and
//! `specs/fulu/polynomial-commitments-sampling.md` rather than like c-kzg's
//! Rust bindings.
//!
//! c-kzg's public API stops short of two helpers those documents define and
//! whose fixture suites call directly: `compute_challenge` and
//! `compute_verify_cell_kzg_proof_batch_challenge`. Both build a Fiat-Shamir
//! transcript (a domain separator, some fixed-width integers, and the
//! arguments' raw bytes), hash it, and reduce the digest modulo the BLS
//! scalar field. c-kzg keeps them as private steps of its own
//! `compute_blob_kzg_proof`/`verify_blob_kzg_proof` and
//! `verify_cell_kzg_proof_batch` and does not export them, so they are
//! reimplemented here directly from the spec text.
//!
//! Every function accepts untrusted bytes and returns [`Result`] rather than
//! panicking. The deneb spec says as much of its own public functions: they
//! "MUST accept raw bytes as input and perform the required cryptographic
//! normalization before invoking any internal functions" (polynomial
//! commitments, introduction). A blob of the wrong length, a field element
//! that is not canonically reduced, or a byte string that does not decode to
//! a curve point is exactly the input that normalization step exists to
//! reject, and the fixture suites downloaded for this crate test that
//! rejection directly: many cases have `output: null`, meaning the operation
//! must fail rather than panic.

use std::sync::LazyLock;

use num_bigint::BigUint;

use crate::error::{Error, Result, verify};
use crate::hash::hash;
use crate::primitives::{Bytes32, H256, KzgCommitment, KzgProof};

/// The cells (equivalently, proofs) produced from one extended blob: the
/// fulu spec's `CELLS_PER_EXT_BLOB`-length vectors.
type CellsPerExtBlob = [c_kzg::Cell; c_kzg::CELLS_PER_EXT_BLOB];
/// A proof for each cell of an extended blob.
type ProofsPerExtBlob = [KzgProof; c_kzg::CELLS_PER_EXT_BLOB];

/// The Ethereum mainnet trusted setup, parsed once.
///
/// The setup is four thousand G1 points in both monomial and Lagrange form
/// plus sixty-five G2 points, embedded in the `c-kzg` binary by the
/// `ethereum_kzg_settings` feature. Parsing that is not free, and every
/// function in this module needs the result, so a per-call load would repeat
/// the parse on every gossiped blob and every block. `LazyLock` runs it
/// exactly once, on first use; every later call reuses the same settings.
/// c-kzg's own `ethereum_kzg_settings` helper happens to cache internally as
/// well, but wrapping it here keeps that behavior a property of this crate's
/// code rather than an implementation detail of c-kzg's that this crate would
/// otherwise be relying on implicitly.
///
/// The precompute argument (0-15) trades memory for faster
/// `verify_kzg_proof`/`verify_blob_kzg_proof`. Nothing in this crate verifies
/// KZG proofs in a hot loop, so 0 keeps the smaller footprint rather than
/// spending memory on precomputed tables this crate would rarely use.
static KZG_SETTINGS: LazyLock<&'static c_kzg::KzgSettings> =
    LazyLock::new(|| c_kzg::ethereum_kzg_settings(0));

/// Scalar field modulus of BLS12-381: the deneb spec's `BLS_MODULUS`, copied
/// verbatim from its constants table.
const BLS_MODULUS_DECIMAL: &str =
    "52435875175126190479447740508185965837690552500527637822603658699938581184513";

/// `BLS_MODULUS`, parsed once rather than on every challenge computed.
static BLS_MODULUS: LazyLock<BigUint> = LazyLock::new(|| {
    BigUint::parse_bytes(BLS_MODULUS_DECIMAL.as_bytes(), 10)
        .expect("BLS_MODULUS_DECIMAL is a valid base-10 literal")
});

/// Parses raw bytes into a c-kzg blob, rejecting anything but exactly
/// `BYTES_PER_BLOB` bytes.
fn to_blob(bytes: &[u8]) -> Result<c_kzg::Blob> {
    c_kzg::Blob::from_bytes(bytes).map_err(|_| Error::SpecAssert("len(blob) == BYTES_PER_BLOB"))
}

/// Converts a c-kzg commitment into this crate's [`KzgCommitment`], so this
/// module's public functions deal in one commitment type rather than leaking
/// c-kzg's.
fn commitment_from_c_kzg(raw: c_kzg::KzgCommitment) -> KzgCommitment {
    KzgCommitment(raw.to_bytes().into_inner())
}

/// Converts a c-kzg proof into this crate's [`KzgProof`].
fn proof_from_c_kzg(raw: c_kzg::KzgProof) -> KzgProof {
    KzgProof(raw.to_bytes().into_inner())
}

/// Converts a boxed array of c-kzg proofs into this crate's proof type,
/// keeping the result on the heap throughout (`CELLS_PER_EXT_BLOB` proofs of
/// `KZG_POINT_SIZE` bytes each is small, but there is no reason to round-trip
/// it through the stack).
fn proofs_from_c_kzg(
    raw: Box<[c_kzg::KzgProof; c_kzg::CELLS_PER_EXT_BLOB]>,
) -> Box<ProofsPerExtBlob> {
    let converted: Vec<KzgProof> = raw.iter().map(|proof| proof_from_c_kzg(*proof)).collect();
    converted
        .into_boxed_slice()
        .try_into()
        .expect("converted has exactly CELLS_PER_EXT_BLOB elements, one per input proof")
}

/// Converts a c-kzg field element into this crate's [`Bytes32`].
fn bytes32_from_c_kzg(raw: c_kzg::Bytes32) -> Bytes32 {
    H256(*raw.as_ref())
}

/// The specification's `blob_to_kzg_commitment`
/// (`specs/deneb/polynomial-commitments.md#blob_to_kzg_commitment`).
///
/// Fails if `blob` is not exactly `BYTES_PER_BLOB` bytes, or if any of its
/// field elements is not canonically reduced modulo `BLS_MODULUS`.
pub fn blob_to_kzg_commitment(blob: &[u8]) -> Result<KzgCommitment> {
    let blob = to_blob(blob)?;
    KZG_SETTINGS
        .blob_to_kzg_commitment(&blob)
        .map(commitment_from_c_kzg)
        .map_err(|_| Error::SpecAssert("every field element in blob is < BLS_MODULUS"))
}

/// The specification's `compute_kzg_proof`
/// (`specs/deneb/polynomial-commitments.md#compute_kzg_proof`).
///
/// Returns the proof that the polynomial `blob` represents evaluates to `y`
/// at `z`, along with `y` itself. Fails if `blob` is the wrong length, if any
/// of its field elements is not canonical, or if `z` is not canonical.
pub fn compute_kzg_proof(blob: &[u8], z: &Bytes32) -> Result<(KzgProof, Bytes32)> {
    let blob = to_blob(blob)?;
    let z_bytes = c_kzg::Bytes32::new(z.0);
    KZG_SETTINGS
        .compute_kzg_proof(&blob, &z_bytes)
        .map(|(proof, y)| (proof_from_c_kzg(proof), bytes32_from_c_kzg(y)))
        .map_err(|_| Error::SpecAssert("blob and z are valid inputs to compute_kzg_proof"))
}

/// The specification's `compute_blob_kzg_proof`
/// (`specs/deneb/polynomial-commitments.md#compute_blob_kzg_proof`).
///
/// This is the proof gossiped alongside a blob and its commitment, evaluated
/// at the Fiat-Shamir challenge point `compute_challenge` derives from them,
/// rather than at a caller-chosen point. Fails if `blob` is invalid, or if
/// `commitment` is not `blob`'s commitment.
pub fn compute_blob_kzg_proof(blob: &[u8], commitment: &KzgCommitment) -> Result<KzgProof> {
    let blob = to_blob(blob)?;
    let commitment_bytes = c_kzg::Bytes48::new(commitment.0);
    KZG_SETTINGS
        .compute_blob_kzg_proof(&blob, &commitment_bytes)
        .map(proof_from_c_kzg)
        .map_err(|_| Error::SpecAssert("commitment is a valid KZG commitment to blob"))
}

/// The specification's `verify_kzg_proof`
/// (`specs/deneb/polynomial-commitments.md#verify_kzg_proof`).
///
/// Checks that `proof` attests that the polynomial committed to by
/// `commitment` evaluates to `y` at `z`. Fails, rather than returning `false`,
/// if any of the byte strings do not decode to a valid point or a canonical
/// field element.
pub fn verify_kzg_proof(
    commitment: &KzgCommitment,
    z: &Bytes32,
    y: &Bytes32,
    proof: &KzgProof,
) -> Result<bool> {
    let commitment_bytes = c_kzg::Bytes48::new(commitment.0);
    let z_bytes = c_kzg::Bytes32::new(z.0);
    let y_bytes = c_kzg::Bytes32::new(y.0);
    let proof_bytes = c_kzg::Bytes48::new(proof.0);
    KZG_SETTINGS
        .verify_kzg_proof(&commitment_bytes, &z_bytes, &y_bytes, &proof_bytes)
        .map_err(|_| Error::SpecAssert("commitment, z, y, and proof decode to valid points"))
}

/// The specification's `verify_blob_kzg_proof`
/// (`specs/deneb/polynomial-commitments.md#verify_blob_kzg_proof`).
///
/// Checks that `proof` attests that `commitment` commits to `blob`, evaluated
/// at the Fiat-Shamir challenge `compute_challenge` derives from them. Fails,
/// rather than returning `false`, on malformed input.
pub fn verify_blob_kzg_proof(
    blob: &[u8],
    commitment: &KzgCommitment,
    proof: &KzgProof,
) -> Result<bool> {
    let blob = to_blob(blob)?;
    let commitment_bytes = c_kzg::Bytes48::new(commitment.0);
    let proof_bytes = c_kzg::Bytes48::new(proof.0);
    KZG_SETTINGS
        .verify_blob_kzg_proof(&blob, &commitment_bytes, &proof_bytes)
        .map_err(|_| Error::SpecAssert("proof attests that commitment commits to blob"))
}

/// The specification's `verify_blob_kzg_proof_batch`
/// (`specs/deneb/polynomial-commitments.md#verify_blob_kzg_proof_batch`).
///
/// Verifies many (blob, commitment, proof) triples with one random linear
/// combination rather than one pairing check per triple. `blobs`,
/// `commitments`, and `proofs` must have equal length; fails, rather than
/// returning `false`, if they do not, or if any element is malformed.
pub fn verify_blob_kzg_proof_batch(
    blobs: &[&[u8]],
    commitments: &[KzgCommitment],
    proofs: &[KzgProof],
) -> Result<bool> {
    let mut c_kzg_blobs = Vec::with_capacity(blobs.len());
    for blob in blobs {
        c_kzg_blobs.push(to_blob(blob)?);
    }
    let commitment_bytes: Vec<c_kzg::Bytes48> = commitments
        .iter()
        .map(|commitment| c_kzg::Bytes48::new(commitment.0))
        .collect();
    let proof_bytes: Vec<c_kzg::Bytes48> = proofs
        .iter()
        .map(|proof| c_kzg::Bytes48::new(proof.0))
        .collect();
    KZG_SETTINGS
        .verify_blob_kzg_proof_batch(&c_kzg_blobs, &commitment_bytes, &proof_bytes)
        .map_err(|_| Error::SpecAssert("blobs, commitments, and proofs have equal, valid entries"))
}

/// The specification's `compute_cells`
/// (`specs/fulu/polynomial-commitments-sampling.md#compute_cells`).
///
/// Extends `blob`'s polynomial by a factor of two and splits the extension
/// into `CELLS_PER_EXT_BLOB` cells, without the accompanying proofs; see
/// [`compute_cells_and_kzg_proofs`] when the proofs are needed too. Fails if
/// `blob` is invalid.
pub fn compute_cells(blob: &[u8]) -> Result<Box<CellsPerExtBlob>> {
    let blob = to_blob(blob)?;
    KZG_SETTINGS
        .compute_cells(&blob)
        .map_err(|_| Error::SpecAssert("blob is the evaluation of a valid polynomial"))
}

/// The specification's `compute_cells_and_kzg_proofs`
/// (`specs/fulu/polynomial-commitments-sampling.md#compute_cells_and_kzg_proofs`).
///
/// Same extension as [`compute_cells`], plus a KZG proof for each cell.
/// Fails if `blob` is invalid.
pub fn compute_cells_and_kzg_proofs(
    blob: &[u8],
) -> Result<(Box<CellsPerExtBlob>, Box<ProofsPerExtBlob>)> {
    let blob = to_blob(blob)?;
    let (cells, proofs) = KZG_SETTINGS
        .compute_cells_and_kzg_proofs(&blob)
        .map_err(|_| Error::SpecAssert("blob is the evaluation of a valid polynomial"))?;
    Ok((cells, proofs_from_c_kzg(proofs)))
}

/// The specification's `recover_cells_and_kzg_proofs`
/// (`specs/fulu/polynomial-commitments-sampling.md#recover_cells_and_kzg_proofs`).
///
/// Reconstructs every cell and proof of an extended blob from a partial set,
/// via Reed-Solomon erasure decoding. `cell_indices` and `cells` must have
/// equal length, with no repeated index; fails if they do not, or if too few
/// cells are given to recover the rest.
pub fn recover_cells_and_kzg_proofs(
    cell_indices: &[u64],
    cells: &[c_kzg::Cell],
) -> Result<(Box<CellsPerExtBlob>, Box<ProofsPerExtBlob>)> {
    let (cells, proofs) = KZG_SETTINGS
        .recover_cells_and_kzg_proofs(cell_indices, cells)
        .map_err(|_| Error::SpecAssert("cell_indices and cells recover a valid extended blob"))?;
    Ok((cells, proofs_from_c_kzg(proofs)))
}

/// The specification's `verify_cell_kzg_proof_batch`
/// (`specs/fulu/polynomial-commitments-sampling.md#verify_cell_kzg_proof_batch`).
///
/// Checks that each `cell` is the evaluation of the polynomial `commitment`
/// commits to, over the domain `cell_index` selects, using `proof`.
/// `commitments`, `cell_indices`, `cells`, and `proofs` must have equal
/// length; fails, rather than returning `false`, if they do not, or if any
/// entry is malformed.
pub fn verify_cell_kzg_proof_batch(
    commitments: &[KzgCommitment],
    cell_indices: &[u64],
    cells: &[c_kzg::Cell],
    proofs: &[KzgProof],
) -> Result<bool> {
    let commitment_bytes: Vec<c_kzg::Bytes48> = commitments
        .iter()
        .map(|commitment| c_kzg::Bytes48::new(commitment.0))
        .collect();
    let proof_bytes: Vec<c_kzg::Bytes48> = proofs
        .iter()
        .map(|proof| c_kzg::Bytes48::new(proof.0))
        .collect();
    KZG_SETTINGS
        .verify_cell_kzg_proof_batch(&commitment_bytes, cell_indices, cells, &proof_bytes)
        .map_err(|_| {
            Error::SpecAssert("commitments, cell_indices, cells, and proofs are consistent")
        })
}

/// Domain separator for `compute_challenge`: the deneb spec's
/// `FIAT_SHAMIR_PROTOCOL_DOMAIN`, copied verbatim.
const FIAT_SHAMIR_PROTOCOL_DOMAIN: &[u8; 16] = b"FSBLOBVERIFY_V1_";

/// Domain separator for `compute_verify_cell_kzg_proof_batch_challenge`: the
/// fulu spec's `RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN`, copied verbatim. Not
/// to be confused with deneb's own `RANDOM_CHALLENGE_KZG_BATCH_DOMAIN`, a
/// different constant this module has no use for because
/// `verify_blob_kzg_proof_batch` above is delegated to c-kzg wholesale.
const RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN: &[u8; 16] = b"RCKZGCBATCH__V1_";

/// The specification's `hash_to_bls_field`
/// (`specs/deneb/polynomial-commitments.md#hash_to_bls_field`): hash `data`
/// and reduce the digest modulo `BLS_MODULUS`, interpreting both the digest
/// and the reduced value big-endian (`KZG_ENDIANNESS`). Shared by both
/// challenge functions below.
///
/// Not exported: like `compute_challenge` and
/// `compute_verify_cell_kzg_proof_batch_challenge`, this is an internal
/// helper the spec document does not flag as a "Public method".
fn hash_to_bls_field(data: &[u8]) -> Bytes32 {
    let digest = hash(data);
    let value = BigUint::from_bytes_be(digest.as_bytes()) % &*BLS_MODULUS;
    let reduced = value.to_bytes_be();

    // `reduced` is big-endian and shorter than 32 bytes whenever the value has
    // leading zero bytes; right-align it so the missing bytes come out zero.
    let mut bytes = [0u8; 32];
    bytes[32 - reduced.len()..].copy_from_slice(&reduced);
    H256(bytes)
}

/// The specification's `compute_challenge`
/// (`specs/deneb/polynomial-commitments.md#compute_challenge`): the
/// Fiat-Shamir challenge point at which `compute_blob_kzg_proof` and
/// `verify_blob_kzg_proof` evaluate `blob`'s polynomial.
///
/// c-kzg computes this internally as a step of those two functions but does
/// not export it; it is reimplemented here directly from the spec text so
/// the standalone `compute_challenge` fixtures, which call it in isolation,
/// can be checked.
///
/// Fails if `blob` is not exactly `BYTES_PER_BLOB` bytes. Unlike the
/// functions above, this never fails on the *content* of `blob` or
/// `commitment`: the transcript is their raw bytes, hashed, with no
/// curve-point or field-element validation performed along the way.
pub fn compute_challenge(blob: &[u8], commitment: &KzgCommitment) -> Result<Bytes32> {
    verify(
        blob.len() == c_kzg::BYTES_PER_BLOB,
        "len(blob) == BYTES_PER_BLOB",
    )?;

    let mut data = Vec::with_capacity(
        FIAT_SHAMIR_PROTOCOL_DOMAIN.len() + 16 + blob.len() + commitment.0.len(),
    );
    data.extend_from_slice(FIAT_SHAMIR_PROTOCOL_DOMAIN);
    // The degree of the polynomial, as a domain separator. The spec encodes
    // it as a 16-byte big-endian integer here (`int.to_bytes(FIELD_ELEMENTS_PER_BLOB, 16, KZG_ENDIANNESS)`);
    // `compute_verify_cell_kzg_proof_batch_challenge` below encodes every
    // integer in its own transcript as 8 bytes instead, so the width is not
    // interchangeable between the two functions.
    data.extend_from_slice(&(c_kzg::FIELD_ELEMENTS_PER_BLOB as u128).to_be_bytes());
    data.extend_from_slice(blob);
    data.extend_from_slice(commitment.as_ref());

    Ok(hash_to_bls_field(&data))
}

/// The specification's `compute_verify_cell_kzg_proof_batch_challenge`
/// (`specs/fulu/polynomial-commitments-sampling.md#compute_verify_cell_kzg_proof_batch_challenge`):
/// the random challenge `r` the universal verification equation in
/// `verify_cell_kzg_proof_batch` uses to combine many cell proofs into one
/// check.
///
/// c-kzg computes this internally as a step of its own
/// `verify_cell_kzg_proof_batch` but does not export it; it is reimplemented
/// here directly from the spec text so the standalone fixtures for it, which
/// call it in isolation, can be checked.
///
/// `commitments` must already be deduplicated and `commitment_indices` must
/// map each coset back to its entry, exactly as `verify_cell_kzg_proof_batch`
/// constructs them internally; this function does not deduplicate on the
/// caller's behalf. `commitment_indices`, `cell_indices`, and `proofs` must
/// each have one entry per element of `cosets_evals`, and each coset's
/// evaluations must number `FIELD_ELEMENTS_PER_CELL`; this function returns
/// `Err` rather than indexing out of bounds if they do not.
pub fn compute_verify_cell_kzg_proof_batch_challenge(
    commitments: &[KzgCommitment],
    commitment_indices: &[u64],
    cell_indices: &[u64],
    cosets_evals: &[Vec<Bytes32>],
    proofs: &[KzgProof],
) -> Result<Bytes32> {
    verify(
        commitment_indices.len() == cosets_evals.len(),
        "commitment_indices has one entry per coset",
    )?;
    verify(
        cell_indices.len() == cosets_evals.len(),
        "cell_indices has one entry per coset",
    )?;
    verify(
        proofs.len() == cosets_evals.len(),
        "proofs has one entry per coset",
    )?;
    for coset_evals in cosets_evals {
        verify(
            coset_evals.len() == c_kzg::FIELD_ELEMENTS_PER_CELL,
            "each coset has FIELD_ELEMENTS_PER_CELL evaluations",
        )?;
    }

    let mut data = Vec::new();
    data.extend_from_slice(RANDOM_CHALLENGE_KZG_CELL_BATCH_DOMAIN);
    // Unlike `compute_challenge` above, every integer in this transcript is
    // an 8-byte big-endian encoding (the spec's `int.to_bytes(_, 8, KZG_ENDIANNESS)`).
    data.extend_from_slice(&(c_kzg::FIELD_ELEMENTS_PER_BLOB as u64).to_be_bytes());
    data.extend_from_slice(&(c_kzg::FIELD_ELEMENTS_PER_CELL as u64).to_be_bytes());
    data.extend_from_slice(&(commitments.len() as u64).to_be_bytes());
    data.extend_from_slice(&(cell_indices.len() as u64).to_be_bytes());
    for commitment in commitments {
        data.extend_from_slice(commitment.as_ref());
    }
    for (k, coset_evals) in cosets_evals.iter().enumerate() {
        data.extend_from_slice(&commitment_indices[k].to_be_bytes());
        data.extend_from_slice(&cell_indices[k].to_be_bytes());
        for coset_eval in coset_evals {
            data.extend_from_slice(coset_eval.as_bytes());
        }
        data.extend_from_slice(proofs[k].as_ref());
    }

    Ok(hash_to_bls_field(&data))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use serde_yaml_ng::Value;

    use super::*;

    /// Root of the downloaded consensus spec test fixtures.
    ///
    /// The fixture harness other stages of this crate share does not exist
    /// yet (it lands in a later stage), so this test module loads its own
    /// small subset of it: KZG fixtures are plain YAML with hex strings, no
    /// SSZ and no snappy compression, so no shared machinery is needed.
    fn fixtures_root() -> PathBuf {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../consensus-spec-tests/tests");
        if !root.exists() {
            panic!(
                "consensus spec test fixtures not found at {}; run `make consensus-spec-tests`",
                root.display()
            );
        }
        root
    }

    /// Loads every `data.yaml` under `general/<fork>/kzg/<handler>/kzg-mainnet/*/`.
    fn cases(fork: &str, handler: &str) -> Vec<Value> {
        let dir = fixtures_root()
            .join("general")
            .join(fork)
            .join("kzg")
            .join(handler)
            .join("kzg-mainnet");
        let entries = fs::read_dir(&dir)
            .unwrap_or_else(|err| panic!("reading fixture directory {}: {err}", dir.display()));
        entries
            .map(|entry| {
                let case_dir = entry.expect("readable directory entry").path();
                let data = fs::read(case_dir.join("data.yaml"))
                    .unwrap_or_else(|err| panic!("reading {}: {err}", case_dir.display()));
                serde_yaml_ng::from_slice(&data)
                    .unwrap_or_else(|err| panic!("parsing {}: {err}", case_dir.display()))
            })
            .collect()
    }

    /// Decodes a `0x`-prefixed hex string into heap-allocated bytes. Blobs
    /// are `BYTES_PER_BLOB` (128 KiB) each, so this, not a stack array, is how
    /// every hex field in this test module is decoded.
    fn hex_bytes(value: &Value) -> Vec<u8> {
        let hex_str = value.as_str().expect("value is a hex string");
        hex::decode(
            hex_str
                .strip_prefix("0x")
                .expect("hex string has a 0x prefix"),
        )
        .expect("value is valid hex")
    }

    /// Decodes a 32-byte hex string, or `None` if it is not exactly 32 bytes.
    /// A length mismatch is treated the same way the upstream c-kzg test
    /// harness treats one: as a case whose expected output must be `null`,
    /// since this crate's typed KZG functions cannot even be called with a
    /// malformed-length field element.
    fn hex_bytes32(value: &Value) -> Option<Bytes32> {
        let bytes = hex_bytes(value);
        let bytes: [u8; 32] = bytes.try_into().ok()?;
        Some(H256(bytes))
    }

    /// Decodes a 48-byte hex string into a [`KzgCommitment`], or `None` if it
    /// is not exactly 48 bytes.
    fn hex_commitment(value: &Value) -> Option<KzgCommitment> {
        let bytes = hex_bytes(value);
        let bytes: [u8; 48] = bytes.try_into().ok()?;
        Some(KzgCommitment(bytes))
    }

    /// Decodes a 48-byte hex string into a [`KzgProof`], or `None` if it is
    /// not exactly 48 bytes.
    fn hex_proof(value: &Value) -> Option<KzgProof> {
        let bytes = hex_bytes(value);
        let bytes: [u8; 48] = bytes.try_into().ok()?;
        Some(KzgProof(bytes))
    }

    /// Decodes a `BYTES_PER_CELL`-byte hex string into a [`c_kzg::Cell`], or
    /// `None` if the length is wrong.
    fn hex_cell(value: &Value) -> Option<c_kzg::Cell> {
        c_kzg::Cell::from_bytes(&hex_bytes(value)).ok()
    }

    #[test]
    fn blob_to_kzg_commitment_matches_fixtures() {
        let cases = cases("deneb", "blob_to_kzg_commitment");
        assert!(
            !cases.is_empty(),
            "no blob_to_kzg_commitment fixtures found"
        );
        for case in &cases {
            let blob = hex_bytes(&case["input"]["blob"]);
            let expected = &case["output"];
            match blob_to_kzg_commitment(&blob) {
                Ok(commitment) => {
                    assert_eq!(Some(commitment), hex_commitment(expected));
                }
                Err(_) => assert!(expected.is_null()),
            }
        }
        println!("blob_to_kzg_commitment: {} cases", cases.len());
    }

    #[test]
    fn compute_kzg_proof_matches_fixtures() {
        let cases = cases("deneb", "compute_kzg_proof");
        assert!(!cases.is_empty(), "no compute_kzg_proof fixtures found");
        for case in &cases {
            let blob = hex_bytes(&case["input"]["blob"]);
            let expected = &case["output"];
            let Some(z) = hex_bytes32(&case["input"]["z"]) else {
                assert!(expected.is_null());
                continue;
            };
            match compute_kzg_proof(&blob, &z) {
                Ok((proof, y)) => {
                    let expected = expected.as_sequence().expect("output is [proof, y]");
                    assert_eq!(Some(proof), hex_proof(&expected[0]));
                    assert_eq!(Some(y), hex_bytes32(&expected[1]));
                }
                Err(_) => assert!(expected.is_null()),
            }
        }
        println!("compute_kzg_proof: {} cases", cases.len());
    }

    #[test]
    fn compute_blob_kzg_proof_matches_fixtures() {
        let cases = cases("deneb", "compute_blob_kzg_proof");
        assert!(
            !cases.is_empty(),
            "no compute_blob_kzg_proof fixtures found"
        );
        for case in &cases {
            let blob = hex_bytes(&case["input"]["blob"]);
            let expected = &case["output"];
            let Some(commitment) = hex_commitment(&case["input"]["commitment"]) else {
                assert!(expected.is_null());
                continue;
            };
            match compute_blob_kzg_proof(&blob, &commitment) {
                Ok(proof) => assert_eq!(Some(proof), hex_proof(expected)),
                Err(_) => assert!(expected.is_null()),
            }
        }
        println!("compute_blob_kzg_proof: {} cases", cases.len());
    }

    #[test]
    fn verify_kzg_proof_matches_fixtures() {
        let cases = cases("deneb", "verify_kzg_proof");
        assert!(!cases.is_empty(), "no verify_kzg_proof fixtures found");
        for case in &cases {
            let expected = &case["output"];
            let input = &case["input"];
            let (Some(commitment), Some(z), Some(y), Some(proof)) = (
                hex_commitment(&input["commitment"]),
                hex_bytes32(&input["z"]),
                hex_bytes32(&input["y"]),
                hex_proof(&input["proof"]),
            ) else {
                assert!(expected.is_null());
                continue;
            };
            match verify_kzg_proof(&commitment, &z, &y, &proof) {
                Ok(verified) => assert_eq!(Some(verified), expected.as_bool()),
                Err(_) => assert!(expected.is_null()),
            }
        }
        println!("verify_kzg_proof: {} cases", cases.len());
    }

    #[test]
    fn verify_blob_kzg_proof_matches_fixtures() {
        let cases = cases("deneb", "verify_blob_kzg_proof");
        assert!(!cases.is_empty(), "no verify_blob_kzg_proof fixtures found");
        for case in &cases {
            let expected = &case["output"];
            let input = &case["input"];
            let blob = hex_bytes(&input["blob"]);
            let (Some(commitment), Some(proof)) = (
                hex_commitment(&input["commitment"]),
                hex_proof(&input["proof"]),
            ) else {
                assert!(expected.is_null());
                continue;
            };
            match verify_blob_kzg_proof(&blob, &commitment, &proof) {
                Ok(verified) => assert_eq!(Some(verified), expected.as_bool()),
                Err(_) => assert!(expected.is_null()),
            }
        }
        println!("verify_blob_kzg_proof: {} cases", cases.len());
    }

    #[test]
    fn verify_blob_kzg_proof_batch_matches_fixtures() {
        let cases = cases("deneb", "verify_blob_kzg_proof_batch");
        assert!(
            !cases.is_empty(),
            "no verify_blob_kzg_proof_batch fixtures found"
        );
        for case in &cases {
            let expected = &case["output"];
            let input = &case["input"];
            let blobs: Vec<Vec<u8>> = input["blobs"]
                .as_sequence()
                .expect("blobs is a list")
                .iter()
                .map(hex_bytes)
                .collect();
            let blob_refs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();

            let commitments: Option<Vec<KzgCommitment>> = input["commitments"]
                .as_sequence()
                .expect("commitments is a list")
                .iter()
                .map(hex_commitment)
                .collect();
            let proofs: Option<Vec<KzgProof>> = input["proofs"]
                .as_sequence()
                .expect("proofs is a list")
                .iter()
                .map(hex_proof)
                .collect();
            let (Some(commitments), Some(proofs)) = (commitments, proofs) else {
                assert!(expected.is_null());
                continue;
            };

            match verify_blob_kzg_proof_batch(&blob_refs, &commitments, &proofs) {
                Ok(verified) => assert_eq!(Some(verified), expected.as_bool()),
                Err(_) => assert!(expected.is_null()),
            }
        }
        println!("verify_blob_kzg_proof_batch: {} cases", cases.len());
    }

    #[test]
    fn compute_cells_matches_fixtures() {
        let cases = cases("fulu", "compute_cells");
        assert!(!cases.is_empty(), "no compute_cells fixtures found");
        for case in &cases {
            let blob = hex_bytes(&case["input"]["blob"]);
            let expected = &case["output"];
            match compute_cells(&blob) {
                Ok(cells) => {
                    let expected = expected.as_sequence().expect("output is a list of cells");
                    assert_eq!(cells.len(), expected.len());
                    for (cell, expected_cell) in cells.iter().zip(expected) {
                        assert_eq!(Some(*cell), hex_cell(expected_cell));
                    }
                }
                Err(_) => assert!(expected.is_null()),
            }
        }
        println!("compute_cells: {} cases", cases.len());
    }

    #[test]
    fn compute_cells_and_kzg_proofs_matches_fixtures() {
        let cases = cases("fulu", "compute_cells_and_kzg_proofs");
        assert!(
            !cases.is_empty(),
            "no compute_cells_and_kzg_proofs fixtures found"
        );
        for case in &cases {
            let blob = hex_bytes(&case["input"]["blob"]);
            let expected = &case["output"];
            match compute_cells_and_kzg_proofs(&blob) {
                Ok((cells, proofs)) => {
                    let expected = expected.as_sequence().expect("output is [cells, proofs]");
                    let expected_cells = expected[0].as_sequence().expect("cells is a list");
                    let expected_proofs = expected[1].as_sequence().expect("proofs is a list");
                    for (cell, expected_cell) in cells.iter().zip(expected_cells) {
                        assert_eq!(Some(*cell), hex_cell(expected_cell));
                    }
                    for (proof, expected_proof) in proofs.iter().zip(expected_proofs) {
                        assert_eq!(Some(*proof), hex_proof(expected_proof));
                    }
                }
                Err(_) => assert!(expected.is_null()),
            }
        }
        println!("compute_cells_and_kzg_proofs: {} cases", cases.len());
    }

    #[test]
    fn recover_cells_and_kzg_proofs_matches_fixtures() {
        let cases = cases("fulu", "recover_cells_and_kzg_proofs");
        assert!(
            !cases.is_empty(),
            "no recover_cells_and_kzg_proofs fixtures found"
        );
        for case in &cases {
            let expected = &case["output"];
            let input = &case["input"];
            let cell_indices: Vec<u64> = input["cell_indices"]
                .as_sequence()
                .expect("cell_indices is a list")
                .iter()
                .map(|v| v.as_u64().expect("cell index is an integer"))
                .collect();
            let cells: Option<Vec<c_kzg::Cell>> = input["cells"]
                .as_sequence()
                .expect("cells is a list")
                .iter()
                .map(hex_cell)
                .collect();
            let Some(cells) = cells else {
                assert!(expected.is_null());
                continue;
            };

            match recover_cells_and_kzg_proofs(&cell_indices, &cells) {
                Ok((recovered_cells, recovered_proofs)) => {
                    let expected = expected.as_sequence().expect("output is [cells, proofs]");
                    let expected_cells = expected[0].as_sequence().expect("cells is a list");
                    let expected_proofs = expected[1].as_sequence().expect("proofs is a list");
                    for (cell, expected_cell) in recovered_cells.iter().zip(expected_cells) {
                        assert_eq!(Some(*cell), hex_cell(expected_cell));
                    }
                    for (proof, expected_proof) in recovered_proofs.iter().zip(expected_proofs) {
                        assert_eq!(Some(*proof), hex_proof(expected_proof));
                    }
                }
                Err(_) => assert!(expected.is_null()),
            }
        }
        println!("recover_cells_and_kzg_proofs: {} cases", cases.len());
    }

    #[test]
    fn verify_cell_kzg_proof_batch_matches_fixtures() {
        let cases = cases("fulu", "verify_cell_kzg_proof_batch");
        assert!(
            !cases.is_empty(),
            "no verify_cell_kzg_proof_batch fixtures found"
        );
        for case in &cases {
            let expected = &case["output"];
            let input = &case["input"];
            let cell_indices: Vec<u64> = input["cell_indices"]
                .as_sequence()
                .expect("cell_indices is a list")
                .iter()
                .map(|v| v.as_u64().expect("cell index is an integer"))
                .collect();

            let commitments: Option<Vec<KzgCommitment>> = input["commitments"]
                .as_sequence()
                .expect("commitments is a list")
                .iter()
                .map(hex_commitment)
                .collect();
            let cells: Option<Vec<c_kzg::Cell>> = input["cells"]
                .as_sequence()
                .expect("cells is a list")
                .iter()
                .map(hex_cell)
                .collect();
            let proofs: Option<Vec<KzgProof>> = input["proofs"]
                .as_sequence()
                .expect("proofs is a list")
                .iter()
                .map(hex_proof)
                .collect();
            let (Some(commitments), Some(cells), Some(proofs)) = (commitments, cells, proofs)
            else {
                assert!(expected.is_null());
                continue;
            };

            match verify_cell_kzg_proof_batch(&commitments, &cell_indices, &cells, &proofs) {
                Ok(verified) => assert_eq!(Some(verified), expected.as_bool()),
                Err(_) => assert!(expected.is_null()),
            }
        }
        println!("verify_cell_kzg_proof_batch: {} cases", cases.len());
    }

    #[test]
    fn compute_challenge_matches_fixtures() {
        let cases = cases("deneb", "compute_challenge");
        assert!(!cases.is_empty(), "no compute_challenge fixtures found");
        for case in &cases {
            let blob = hex_bytes(&case["input"]["blob"]);
            let expected = &case["output"];
            let Some(commitment) = hex_commitment(&case["input"]["commitment"]) else {
                assert!(expected.is_null());
                continue;
            };
            match compute_challenge(&blob, &commitment) {
                Ok(challenge) => assert_eq!(Some(challenge), hex_bytes32(expected)),
                Err(_) => assert!(expected.is_null()),
            }
        }
        println!("compute_challenge: {} cases", cases.len());
    }

    #[test]
    fn compute_verify_cell_kzg_proof_batch_challenge_matches_fixtures() {
        let cases = cases("fulu", "compute_verify_cell_kzg_proof_batch_challenge");
        assert!(
            !cases.is_empty(),
            "no compute_verify_cell_kzg_proof_batch_challenge fixtures found"
        );
        for case in &cases {
            let expected = &case["output"];
            let input = &case["input"];

            let commitments: Option<Vec<KzgCommitment>> = input["commitments"]
                .as_sequence()
                .expect("commitments is a list")
                .iter()
                .map(hex_commitment)
                .collect();
            let commitment_indices: Vec<u64> = input["commitment_indices"]
                .as_sequence()
                .expect("commitment_indices is a list")
                .iter()
                .map(|v| v.as_u64().expect("commitment index is an integer"))
                .collect();
            let cell_indices: Vec<u64> = input["cell_indices"]
                .as_sequence()
                .expect("cell_indices is a list")
                .iter()
                .map(|v| v.as_u64().expect("cell index is an integer"))
                .collect();
            let cosets_evals: Option<Vec<Vec<Bytes32>>> = input["cosets_evals"]
                .as_sequence()
                .expect("cosets_evals is a list")
                .iter()
                .map(|coset| {
                    coset
                        .as_sequence()
                        .expect("coset is a list of field elements")
                        .iter()
                        .map(hex_bytes32)
                        .collect::<Option<Vec<_>>>()
                })
                .collect();
            let proofs: Option<Vec<KzgProof>> = input["proofs"]
                .as_sequence()
                .expect("proofs is a list")
                .iter()
                .map(hex_proof)
                .collect();
            let (Some(commitments), Some(cosets_evals), Some(proofs)) =
                (commitments, cosets_evals, proofs)
            else {
                assert!(expected.is_null());
                continue;
            };

            match compute_verify_cell_kzg_proof_batch_challenge(
                &commitments,
                &commitment_indices,
                &cell_indices,
                &cosets_evals,
                &proofs,
            ) {
                Ok(challenge) => assert_eq!(Some(challenge), hex_bytes32(expected)),
                Err(_) => assert!(expected.is_null()),
            }
        }
        println!(
            "compute_verify_cell_kzg_proof_batch_challenge: {} cases",
            cases.len()
        );
    }
}
