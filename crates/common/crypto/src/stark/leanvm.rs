//! Attestation proofs made and checked by leanVM in this process (bindings
//! v0.17.0, [`LEANVM_REV`]).
//!
//! The PQ devnet does not run the specification's reference concatenation:
//! its clients prove with leanVM. pq-devnet-0 did it through a separate
//! `leanvm-sidecar` process; v0.17.0 removed the sidecar, and every client now
//! proves in-process through `lean_vm`'s `setup`, `aggregate` and
//! `AggregateProof::{from_bytes, verify}`. Proofs only verify against a
//! verifier of the same release, and nothing on the wire says so: a proof from
//! another revision simply fails to verify.
//!
//! The mapping from the specification's statements is Lighthouse's, so the
//! two clients' proofs verify against each other:
//!
//! - A leanVM proof attests `(public key, message)` claims. A statement list
//!   flattens to the sorted, deduplicated list of its pairs (the verifier only
//!   accepts a claim list strictly sorted by the 64 bytes `pubkey || message`).
//! - **The leaf index is not part of a claim** (leanEthereum/leanVM#787), so
//!   [`LeanVmBackend::verify`] shows each key signed the message at *some*
//!   leaf, not at the statement's. [`LeanVmBackend::prove`] refuses
//!   signatures made at another leaf, since it sees them.
//! - The empty proof stands for "nothing to prove" (leanVM refuses to prove
//!   zero claims), and verifies only against no claims.
//! - A merge folds the children [`MAX_CHILDREN_PER_AGGREGATE`] at a time,
//!   round after round, until one proof remains.
//!
//! leanVM runs one proof at a time per process ("a second waits for the
//! first"), on a thread pool of its own that [`LeanVmBackend::setup`] starts.
//! Verification does not wait for a proof in progress.

use std::time::Instant;

use leanvm_claims::{AggregateClaims, OutputClaims};
use leanvm_lean_xmss::{LeanXmssPublicKey, LeanXmssSignature};
use leanvm_prover::AggregateProof;

use super::{AggregateStatement, ProveError};
use crate::lean_xmss::{self, Message, PUBKEY_SIZE, SIGNATURE_SIZE};

/// The most children one aggregate takes (leanVM's `MAX_RECURSIONS`).
pub const MAX_CHILDREN_PER_AGGREGATE: usize = leanvm_prover::MAX_RECURSIONS;

/// The leanVM revision the workspace proves and verifies with (bindings
/// v0.17.0). Every node of a network must run the same one.
pub const LEANVM_REV: &str = "1e997c9927d3e7fafa2b813734f56e25d7a4da69";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("leanVM: {0}")]
    LeanVm(String),
    #[error("a proof backend is already installed")]
    AlreadyInstalled,
    #[error("leanVM proved {found} claims, {expected} were asked")]
    ClaimsMismatch { expected: usize, found: usize },
    #[error("child {0} has claims and an empty proof, or a proof and no claims")]
    MalformedChild(usize),
    #[error("child {0}'s proof does not decode")]
    UndecodableChild(usize),
    #[error("log_inv_rate {0} is outside leanVM's {min}..={max}", min = leanvm_prover::MIN_LOG_INV_RATE, max = leanvm_prover::MAX_LOG_INV_RATE)]
    LogInvRate(u8),
}

impl From<Error> for ProveError {
    fn from(error: Error) -> Self {
        ProveError::LeanVm(error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeanVmConfig {
    /// How many threads leanVM's prover pool runs, 0 for one per core.
    pub threads: usize,
    /// `log_inv_rate` of the proofs made, within leanVM's bounds: a higher
    /// rate gives smaller proofs that take longer to make. A proof verifies
    /// whatever rate it was made at.
    pub log_inv_rate: u8,
}

impl Default for LeanVmConfig {
    /// One thread per core, at the rate pq-devnet-0's sidecars proved at
    /// (Lighthouse's default).
    fn default() -> Self {
        Self {
            threads: 0,
            log_inv_rate: 2,
        }
    }
}

pub struct LeanVmBackend {
    log_inv_rate: usize,
}

impl LeanVmBackend {
    /// Starts leanVM's prover pool and builds its aggregation program, which
    /// verifying needs too. Takes seconds; call once, at startup.
    pub fn setup(config: LeanVmConfig) -> Result<Self, Error> {
        let rate = usize::from(config.log_inv_rate);
        if !(leanvm_prover::MIN_LOG_INV_RATE..=leanvm_prover::MAX_LOG_INV_RATE).contains(&rate) {
            return Err(Error::LogInvRate(config.log_inv_rate));
        }
        let started = Instant::now();
        leanvm_prover::setup(config.threads);
        tracing::info!(
            threads = config.threads,
            log_inv_rate = config.log_inv_rate,
            leanvm_rev = LEANVM_REV,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "leanVM prover ready, in process"
        );
        Ok(Self { log_inv_rate: rate })
    }

    pub(super) fn prove<S: AsRef<[u8]>>(
        &self,
        statements: &[AggregateStatement],
        signatures: &[Vec<S>],
    ) -> Result<Vec<u8>, ProveError> {
        for (statement_index, (statement, group)) in statements.iter().zip(signatures).enumerate() {
            for (signature_index, signature) in group.iter().enumerate() {
                let found = lean_xmss::signature_index(signature.as_ref()).unwrap_or(u64::MAX);
                if found != statement.leaf_index {
                    return Err(ProveError::LeafIndex {
                        statement: statement_index,
                        signature: signature_index,
                        expected: statement.leaf_index,
                        found,
                    });
                }
            }
        }
        let expected = statements_to_claims(statements);
        if expected.lean_xmss.is_empty() {
            return Ok(Vec::new());
        }
        let raw_signatures: Vec<_> = statements
            .iter()
            .zip(signatures)
            .flat_map(|(statement, group)| {
                statement
                    .pubkeys
                    .iter()
                    .zip(group)
                    .map(|(pubkey, signature)| {
                        let signature: &[u8; SIGNATURE_SIZE] = signature
                            .as_ref()
                            .try_into()
                            .expect("check_shape bounds every signature's length");
                        (
                            LeanXmssPublicKey::from_bytes(pubkey),
                            statement.message,
                            LeanXmssSignature::from_bytes(signature),
                        )
                    })
            })
            .collect();
        let proof = self.aggregate(&[], raw_signatures, &expected)?;
        Ok(proof.to_bytes())
    }

    pub(super) fn merge<S: AsRef<[AggregateStatement]>, P: AsRef<[u8]>>(
        &self,
        children: &[(S, P)],
    ) -> Result<Vec<u8>, ProveError> {
        let mut level: Vec<(AggregateClaims, AggregateProof)> = Vec::with_capacity(children.len());
        for (index, (statements, proof)) in children.iter().enumerate() {
            let claims = statements_to_claims(statements.as_ref());
            match (claims.lean_xmss.is_empty(), proof.as_ref().is_empty()) {
                (true, true) => {}
                (false, false) => {
                    let proof = AggregateProof::from_bytes(proof.as_ref())
                        .ok_or(Error::UndecodableChild(index))?;
                    level.push((claims, proof));
                }
                _ => return Err(Error::MalformedChild(index).into()),
            }
        }
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(MAX_CHILDREN_PER_AGGREGATE));
            let mut rest = level.into_iter().peekable();
            while rest.peek().is_some() {
                let chunk: Vec<_> = rest.by_ref().take(MAX_CHILDREN_PER_AGGREGATE).collect();
                if chunk.len() == 1 {
                    next.extend(chunk);
                    continue;
                }
                let expected = union(&chunk);
                let proof = self.aggregate(&chunk, Vec::new(), &expected)?;
                next.push((expected, proof));
            }
            level = next;
        }
        Ok(level
            .pop()
            .map(|(_, proof)| proof.to_bytes())
            .unwrap_or_default())
    }

    pub(super) fn verify(&self, statements: &[AggregateStatement], proof: &[u8]) -> bool {
        let claims = statements_to_claims(statements);
        if claims.lean_xmss.is_empty() || proof.is_empty() {
            return claims.lean_xmss.is_empty() && proof.is_empty();
        }
        AggregateProof::from_bytes(proof).is_some_and(|proof| proof.verify(&claims))
    }

    /// One aggregate. Checks leanVM proved exactly `expected`.
    fn aggregate(
        &self,
        children: &[(AggregateClaims, AggregateProof)],
        raw_signatures: Vec<(LeanXmssPublicKey, Message, LeanXmssSignature)>,
        expected: &AggregateClaims,
    ) -> Result<AggregateProof, Error> {
        let started = Instant::now();
        let signatures = raw_signatures.len();
        let (claims, proof) = leanvm_prover::aggregate(
            children,
            raw_signatures,
            Vec::new(),
            None,
            OutputClaims::All,
            self.log_inv_rate,
        )
        .map_err(|err| Error::LeanVm(err.to_string()))?;
        if claims != *expected {
            return Err(Error::ClaimsMismatch {
                expected: expected.num_signature_claims(),
                found: claims.num_signature_claims(),
            });
        }
        tracing::debug!(
            children = children.len(),
            signatures,
            claims = claims.num_signature_claims(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "Proved an attestation aggregate"
        );
        Ok(proof)
    }
}

/// The claims a proof of `statements` attests: every `(pubkey, message)`
/// pair, strictly sorted by its bytes, without duplicates. No leanSPHINCS
/// claims and no DA commitment.
pub fn statements_to_claims(statements: &[AggregateStatement]) -> AggregateClaims {
    let mut pairs: Vec<([u8; PUBKEY_SIZE], Message)> = statements
        .iter()
        .flat_map(|statement| {
            statement
                .pubkeys
                .iter()
                .map(|pubkey| (*pubkey, statement.message))
        })
        .collect();
    // Tuples of byte arrays order as their concatenation does.
    pairs.sort_unstable();
    pairs.dedup();
    AggregateClaims {
        lean_xmss: pairs
            .into_iter()
            .map(|(pubkey, message)| (LeanXmssPublicKey::from_bytes(&pubkey), message))
            .collect(),
        lean_sphincs: Vec::new(),
        da_commitment: None,
    }
}

/// The claims a proof of all of `children` attests: their union, strictly
/// sorted.
fn union(children: &[(AggregateClaims, AggregateProof)]) -> AggregateClaims {
    let mut lean_xmss: Vec<_> = children
        .iter()
        .flat_map(|(claims, _)| claims.lean_xmss.iter().copied())
        .collect();
    lean_xmss.sort_unstable();
    lean_xmss.dedup();
    AggregateClaims {
        lean_xmss,
        lean_sphincs: Vec::new(),
        da_commitment: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statement(
        pubkeys: &[[u8; PUBKEY_SIZE]],
        leaf_index: u64,
        message: Message,
    ) -> AggregateStatement {
        AggregateStatement {
            pubkeys: pubkeys.to_vec(),
            leaf_index,
            message,
        }
    }

    #[test]
    fn no_claims_encode_as_empty_lists() {
        let expected = [0u8; 8 + 8 + 1];
        assert_eq!(statements_to_claims(&[]).to_bytes(), expected);
        assert_eq!(
            statements_to_claims(&[statement(&[], 1, [7; 32])]).to_bytes(),
            expected
        );
    }

    /// Lighthouse's `claims_bytes_match_the_sidecar_format`: out of order within
    /// and across statements, one repeated claim, one key signing two
    /// messages, and no leaf index on the wire.
    #[test]
    fn claims_are_sorted_deduplicated_pairs() {
        let mut low_key = [3; 32];
        low_key[31] = 2;
        let statements = [
            statement(&[[9; 32], [3; 32], low_key], 40_000, [0xaa; 32]),
            statement(&[[3; 32], [1; 32]], 50_000, [0x11; 32]),
            statement(&[[9; 32]], 60_000, [0xaa; 32]),
        ];
        let mut expected = Vec::new();
        expected.extend_from_slice(&5u64.to_le_bytes());
        for (key, message) in [
            ([1; 32], [0x11; 32]),
            (low_key, [0xaa; 32]),
            ([3; 32], [0x11; 32]),
            ([3; 32], [0xaa; 32]),
            ([9; 32], [0xaa; 32]),
        ] {
            expected.extend_from_slice(&key);
            expected.extend_from_slice(&message);
        }
        expected.extend_from_slice(&0u64.to_le_bytes());
        expected.push(0);
        assert_eq!(statements_to_claims(&statements).to_bytes(), expected);
    }

    #[test]
    fn a_rate_outside_leanvms_bounds_is_refused() {
        let config = LeanVmConfig {
            threads: 0,
            log_inv_rate: 0,
        };
        assert!(matches!(
            LeanVmBackend::setup(config),
            Err(Error::LogInvRate(0))
        ));
    }

    /// End to end on leanVM itself: two committees' proofs, merged, verify
    /// against their concatenated statements and nothing else. Seconds of
    /// proving, so ignored by default; `cargo test -p ethlambda-crypto
    /// --profile release-fast -- --ignored leanvm` runs it.
    #[test]
    #[ignore = "proves with leanVM: seconds per proof"]
    fn leanvm_proofs_merge_and_verify() {
        use crate::lean_xmss::range_key;
        let backend = LeanVmBackend::setup(LeanVmConfig::default()).unwrap();
        let signed = |seed: u8, leaf: u32, message: &Message| {
            let key = range_key(&[seed; 32], leaf, leaf);
            let signature = key.sign(message, leaf).unwrap().to_bytes();
            (key.public_key().to_bytes(), signature)
        };
        let (m1, m2): (Message, Message) = ([1; 32], [2; 32]);
        let (a, sig_a) = signed(10, 40, &m1);
        let (b, sig_b) = signed(11, 40, &m1);
        let (c, sig_c) = signed(12, 41, &m2);
        let first = [statement(&[a, b], 40, m1)];
        let second = [statement(&[c], 41, m2)];
        let one = backend.prove(&first, &[vec![&sig_a, &sig_b]]).unwrap();
        let two = backend.prove(&second, &[vec![&sig_c]]).unwrap();
        assert!(backend.verify(&first, &one));
        assert!(!backend.verify(&second, &one));
        let merged = backend
            .merge(&[(&first[..], &one[..]), (&second[..], &two[..])])
            .unwrap();
        let both = [first[0].clone(), second[0].clone()];
        assert!(backend.verify(&both, &merged));
        assert!(!backend.verify(&first, &merged));
        assert!(!backend.verify(&both, &merged[..merged.len() - 1]));
    }
}
