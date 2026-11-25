//! The PQ fork's proofs of many leanXMSS signatures at once (the
//! specification's `stark` module: `ProveAggregates`, `MergeProofs`,
//! `VerifyAggregates`), behind one of two backends, chosen once per process:
//!
//! - **Reference** (the default): the specification's stand-in for a
//!   recursive STARK, which concatenates signatures. A proof is the signatures
//!   of every statement's public keys, in statement order and within a
//!   statement in public-key order, and verification checks each in turn. It
//!   is what the specification's fixtures use.
//! - **leanVM** ([`install_leanvm`]): real leanVM proofs, made and checked
//!   in this process (bindings v0.17.0), as the PQ devnet's other clients make
//!   them. See [`leanvm`].
//!
//! The two encodings are not interchangeable: a node verifies only the proofs
//! its own backend makes, so every node of a network must run the same one.
//! The functions below take the same arguments whichever is installed.
//!
//! Under the reference, the proof is bounded by `MAX_STARK_PROOF_SIZE` (1 MiB),
//! so a block carries at most `MAX_STARK_PROOF_SIZE / SIGNATURE_SIZE` (436)
//! attester signatures. That is a property of the placeholder, not of the fork.

use std::sync::OnceLock;

use rayon::prelude::*;

use crate::lean_xmss::{self, Message, PUBKEY_SIZE, SIGNATURE_SIZE};

pub mod leanvm;

/// The backend every proof of this process goes through.
enum Backend {
    Reference,
    LeanVm(leanvm::LeanVmBackend),
}

static BACKEND: OnceLock<Backend> = OnceLock::new();

fn backend() -> &'static Backend {
    BACKEND.get_or_init(|| Backend::Reference)
}

/// Makes every proof of this process a leanVM proof, made and checked in
/// process, after starting leanVM's prover pool (seconds). Call once, at
/// startup, before anything proves or verifies: whichever backend is first
/// used stays for the life of the process.
pub fn install_leanvm(config: leanvm::LeanVmConfig) -> Result<(), leanvm::Error> {
    if BACKEND.get().is_some() {
        return Err(leanvm::Error::AlreadyInstalled);
    }
    let backend = leanvm::LeanVmBackend::setup(config)?;
    BACKEND
        .set(Backend::LeanVm(backend))
        .map_err(|_| leanvm::Error::AlreadyInstalled)
}

/// The installed backend's name, for logs: `reference` or `leanvm`.
pub fn backend_name() -> &'static str {
    match backend() {
        Backend::Reference => "reference",
        Backend::LeanVm(_) => "leanvm",
    }
}

/// The specification's `XMSSAggregateStatement`: every public key in `pubkeys`
/// signed `message` at `leaf_index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateStatement {
    pub pubkeys: Vec<[u8; PUBKEY_SIZE]>,
    pub leaf_index: u64,
    pub message: Message,
}

/// Why [`prove_aggregates`] or [`merge_proofs`] refused its input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProveError {
    #[error("{statements} statements but {signature_lists} signature lists")]
    StatementCount {
        statements: usize,
        signature_lists: usize,
    },
    #[error("statement {statement} has {pubkeys} public keys but {signatures} signatures")]
    SignatureCount {
        statement: usize,
        pubkeys: usize,
        signatures: usize,
    },
    #[error("a signature is {0} bytes, not {SIGNATURE_SIZE}")]
    SignatureLength(usize),
    #[error("signature {signature} of statement {statement} is at leaf {found}, not {expected}")]
    LeafIndex {
        statement: usize,
        signature: usize,
        expected: u64,
        found: u64,
    },
    #[error("leanVM could not prove: {0}")]
    LeanVm(String),
}

/// `stark.ProveAggregates(statements, signatures)`: `signatures[i][j]` is the
/// signature of `statements[i].pubkeys[j]`. The reference verifies nothing
/// and only asserts the shapes line up; leanVM refuses a signature that does
/// not verify. Blocks the calling thread for as long as the proof takes,
/// which under leanVM is seconds, and leanVM makes one proof at a time.
pub fn prove_aggregates<S: AsRef<[u8]>>(
    statements: &[AggregateStatement],
    signatures: &[Vec<S>],
) -> Result<Vec<u8>, ProveError> {
    check_shape(statements, signatures)?;
    match backend() {
        Backend::Reference => Ok(signatures
            .iter()
            .flatten()
            .flat_map(|signature| signature.as_ref())
            .copied()
            .collect()),
        Backend::LeanVm(leanvm) => leanvm.prove(statements, signatures),
    }
}

/// `stark.MergeProofs(proofs)`: one proof of the concatenation, in order, of
/// the statement lists the children prove. Each child is its statements and
/// its proof. Children are not verified: verify untrusted ones first.
pub fn merge_proofs<S: AsRef<[AggregateStatement]>, P: AsRef<[u8]>>(
    children: &[(S, P)],
) -> Result<Vec<u8>, ProveError> {
    match backend() {
        Backend::Reference => Ok(children
            .iter()
            .flat_map(|(_, proof)| proof.as_ref())
            .copied()
            .collect()),
        Backend::LeanVm(leanvm) => leanvm.merge(children),
    }
}

/// `stark.VerifyAggregates(statements, proof)`. Under the reference, `true`
/// only if `proof` holds, for each statement in turn and each of its public
/// keys in order, a signature `xmss.Verify` accepts at the statement's leaf
/// index and message, and nothing else. Under leanVM, whether the proof
/// proves every `(public key, message)` claim; it cannot check the leaf
/// indices, which leanVM proofs do not attest.
pub fn verify_aggregates(statements: &[AggregateStatement], proof: &[u8]) -> bool {
    match backend() {
        Backend::Reference => reference_verify(statements, proof),
        Backend::LeanVm(leanvm) => leanvm.verify(statements, proof),
    }
}

/// Checks `signatures` has one list per statement and one signature of
/// [`SIGNATURE_SIZE`] bytes per public key.
fn check_shape<S: AsRef<[u8]>>(
    statements: &[AggregateStatement],
    signatures: &[Vec<S>],
) -> Result<(), ProveError> {
    if statements.len() != signatures.len() {
        return Err(ProveError::StatementCount {
            statements: statements.len(),
            signature_lists: signatures.len(),
        });
    }
    for (statement, (index, list)) in statements.iter().zip(signatures.iter().enumerate()) {
        if statement.pubkeys.len() != list.len() {
            return Err(ProveError::SignatureCount {
                statement: index,
                pubkeys: statement.pubkeys.len(),
                signatures: list.len(),
            });
        }
    }
    for signature in signatures.iter().flatten() {
        let bytes = signature.as_ref();
        if bytes.len() != SIGNATURE_SIZE {
            return Err(ProveError::SignatureLength(bytes.len()));
        }
    }
    Ok(())
}

/// The reference's `VerifyAggregates`. The signatures are checked in parallel:
/// they are independent, and a block's proof holds hundreds.
fn reference_verify(statements: &[AggregateStatement], proof: &[u8]) -> bool {
    let claims: Vec<(&[u8; PUBKEY_SIZE], u64, &Message)> = statements
        .iter()
        .flat_map(|statement| {
            statement
                .pubkeys
                .iter()
                .map(move |pubkey| (pubkey, statement.leaf_index, &statement.message))
        })
        .collect();
    if proof.len() != claims.len() * SIGNATURE_SIZE {
        return false;
    }
    claims
        .par_iter()
        .zip(proof.par_chunks_exact(SIGNATURE_SIZE))
        .all(|((pubkey, leaf_index, message), signature)| {
            lean_xmss::verify(pubkey, *leaf_index, message, signature)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lean_xmss::range_key;

    fn signed(seed: u8, leaf: u32, message: &Message) -> ([u8; PUBKEY_SIZE], Vec<u8>) {
        let key = range_key(&[seed; 32], leaf, leaf);
        let signature = key.sign(message, leaf).unwrap().to_bytes();
        (key.public_key().to_bytes(), signature)
    }

    #[test]
    fn a_merged_proof_verifies_against_the_concatenated_statements() {
        let first_message: Message = [1; 32];
        let second_message: Message = [2; 32];
        let (a, sig_a) = signed(10, 40, &first_message);
        let (b, sig_b) = signed(11, 40, &first_message);
        let (c, sig_c) = signed(12, 41, &second_message);
        let first = AggregateStatement {
            pubkeys: vec![a, b],
            leaf_index: 40,
            message: first_message,
        };
        let second = AggregateStatement {
            pubkeys: vec![c],
            leaf_index: 41,
            message: second_message,
        };
        let proof_one =
            prove_aggregates(std::slice::from_ref(&first), &[vec![&sig_a, &sig_b]]).unwrap();
        let proof_two = prove_aggregates(std::slice::from_ref(&second), &[vec![&sig_c]]).unwrap();
        assert!(verify_aggregates(std::slice::from_ref(&first), &proof_one));
        let one = [first.clone()];
        let two = [second.clone()];
        let merged =
            merge_proofs(&[(&one[..], &proof_one[..]), (&two[..], &proof_two[..])]).unwrap();
        let both = [first.clone(), second.clone()];
        assert!(verify_aggregates(&both, &merged));
        // Out of order, short, or with a trailing byte, the same signatures fail.
        assert!(!verify_aggregates(&[second, first], &merged));
        assert!(!verify_aggregates(&both, &merged[..merged.len() - 1]));
        let mut long = merged.clone();
        long.push(0);
        assert!(!verify_aggregates(&both, &long));
    }

    #[test]
    fn no_statements_take_the_empty_proof_only() {
        assert!(verify_aggregates(&[], &[]));
        assert!(!verify_aggregates(&[], &[0; SIGNATURE_SIZE]));
        let empty = AggregateStatement {
            pubkeys: vec![],
            leaf_index: 0,
            message: [0; 32],
        };
        assert!(verify_aggregates(&[empty], &[]));
    }

    #[test]
    fn mismatched_shapes_are_refused() {
        let statement = AggregateStatement {
            pubkeys: vec![[0; PUBKEY_SIZE]],
            leaf_index: 0,
            message: [0; 32],
        };
        assert_eq!(
            prove_aggregates::<Vec<u8>>(std::slice::from_ref(&statement), &[]),
            Err(ProveError::StatementCount {
                statements: 1,
                signature_lists: 0
            })
        );
        assert_eq!(
            prove_aggregates(std::slice::from_ref(&statement), &[vec![vec![0u8; 3]]]),
            Err(ProveError::SignatureLength(3))
        );
    }
}
