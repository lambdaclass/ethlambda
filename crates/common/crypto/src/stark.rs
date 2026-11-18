//! The PQ fork's proofs of many leanXMSS signatures at once (the
//! specification's `stark` module: `ProveAggregates`, `MergeProofs`,
//! `VerifyAggregates`).
//!
//! The specification defines these as a recursive STARK, and its reference
//! implementation stands in for one by concatenating signatures: a proof is the
//! signatures of every statement's public keys, in statement order and within a
//! statement in public-key order, and verification checks each in turn. This
//! module is that reference concatenation, byte for byte, because it is what
//! the specification's fixtures and every other client agree on today. A real
//! STARK would change the encoding of `AttestationProof` but not how these
//! three functions are called.
//!
//! The proof is bounded by `MAX_STARK_PROOF_SIZE` (1 MiB), so a block carries at
//! most `MAX_STARK_PROOF_SIZE / SIGNATURE_SIZE` (436) attester signatures under
//! this encoding. That is a property of the placeholder, not of the fork.

use rayon::prelude::*;

use crate::lean_xmss::{self, Message, PUBKEY_SIZE, SIGNATURE_SIZE};

/// The specification's `XMSSAggregateStatement`: every public key in `pubkeys`
/// signed `message` at `leaf_index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateStatement {
    pub pubkeys: Vec<[u8; PUBKEY_SIZE]>,
    pub leaf_index: u64,
    pub message: Message,
}

/// Why [`prove_aggregates`] refused its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
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
}

/// `stark.ProveAggregates(statements, signatures)`: `signatures[i][j]` is the
/// signature of `statements[i].pubkeys[j]`. Nothing is verified here; the
/// reference only asserts the shapes line up.
pub fn prove_aggregates<S: AsRef<[u8]>>(
    statements: &[AggregateStatement],
    signatures: &[Vec<S>],
) -> Result<Vec<u8>, ProveError> {
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
    let total = signatures.iter().map(Vec::len).sum::<usize>();
    let mut proof = Vec::with_capacity(total * SIGNATURE_SIZE);
    for signature in signatures.iter().flatten() {
        let bytes = signature.as_ref();
        if bytes.len() != SIGNATURE_SIZE {
            return Err(ProveError::SignatureLength(bytes.len()));
        }
        proof.extend_from_slice(bytes);
    }
    Ok(proof)
}

/// `stark.MergeProofs(proofs)`: one proof of the concatenation of the statement
/// lists the inputs prove, in order.
pub fn merge_proofs<P: AsRef<[u8]>>(proofs: &[P]) -> Vec<u8> {
    proofs
        .iter()
        .flat_map(|proof| proof.as_ref())
        .copied()
        .collect()
}

/// `stark.VerifyAggregates(statements, proof)`: `true` only if `proof` holds,
/// for each statement in turn and each of its public keys in order, a
/// signature `xmss.Verify` accepts at the statement's leaf index and message,
/// and nothing else.
///
/// The signatures are checked in parallel: they are independent, and a block's
/// proof holds hundreds.
pub fn verify_aggregates(statements: &[AggregateStatement], proof: &[u8]) -> bool {
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
        let merged = merge_proofs(&[&proof_one, &proof_two]);
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
