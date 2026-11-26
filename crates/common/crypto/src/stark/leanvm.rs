//! Attestation proofs made and checked by leanVM in this process (bindings
//! v0.19.0, [`LEANVM_REV`]).
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
//! Verification takes no lock and runs on the calling thread, so it does not
//! wait for a proof in progress.
//!
//! Every call into leanVM goes through [`guarded`], which catches a panic
//! inside it: see there for why that matters more in process than it did
//! behind a socket.

use std::time::{Duration, Instant};

use leanvm_claims::{AggregateClaims, OutputClaims};
use leanvm_lean_xmss::{LeanXmssPublicKey, LeanXmssSignature};
use leanvm_prover::AggregateProof;

use super::{AggregateStatement, ProveError};
use crate::lean_xmss::{self, Message, PUBKEY_SIZE, SIGNATURE_SIZE};

/// The most children one aggregate takes (leanVM's `MAX_RECURSIONS`).
pub const MAX_CHILDREN_PER_AGGREGATE: usize = leanvm_prover::MAX_RECURSIONS;

/// leanVM's own count of its STARK-breaking changes: proofs and signatures
/// verify between two builds exactly when this is the same in both. What to
/// compare with another client's when a proof of theirs does not verify.
pub const PROTOCOL_VERSION: u32 = leanvm_prover::PROTOCOL_VERSION;

/// The leanVM revision the workspace proves and verifies with (bindings
/// v0.19.0). Every node of a network must run the same one.
pub const LEANVM_REV: &str = "351f7ae421529ce164ed747eee1f78bdeaec3e80";

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
    #[error("leanVM panicked in {call}: {reason}")]
    Panicked { call: &'static str, reason: String },
    #[error("leanVM failed its self-check: {0}")]
    SelfCheck(String),
}

/// Runs one call into leanVM, catching a panic inside it.
///
/// pq-devnet-0 ran leanVM in a sidecar, where an input that crashed it cost
/// a restart of that process. In process, the caller is the thread importing
/// a block or judging gossip, and the proof bytes come from peers: a panic
/// must fail the one proof, not unwind through the chain actor. Verification
/// shares no lock with proving, so it goes on whatever a panic left behind;
/// proving may not (leanVM's signer cache does not tolerate a poisoned lock),
/// and then every later proof fails here the same way, loudly.
fn guarded<T>(call: &'static str, run: impl FnOnce() -> T) -> Result<T, Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).map_err(|panic| {
        let reason = panic
            .downcast_ref::<&str>()
            .map(|reason| (*reason).to_string())
            .or_else(|| panic.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "no message".to_string());
        tracing::error!(call, %reason, "leanVM panicked");
        Error::Panicked { call, reason }
    })
}

/// The seed of the throwaway key [`LeanVmBackend::self_check`] signs with.
/// Public, so the key protects nothing, and the rule that a seed backs one
/// key only ([`lean_xmss::range_key`]) costs it nothing: the check builds it
/// over as many leaves as it is asked to prove.
const SELF_CHECK_SEED: [u8; 32] = *b"ethlambda leanVM self-check key.";

/// The most signatures [`LeanVmBackend::self_check`] proves at once: twice the
/// largest committee, and within the throwaway key's first bottom tree.
pub const MAX_SELF_CHECK_SIGNATURES: u32 = 4096;

/// What [`LeanVmBackend::self_check`] measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfCheck {
    pub signatures: usize,
    pub prove: Duration,
    pub verify: Duration,
    pub proof_bytes: usize,
}

impl From<Error> for ProveError {
    fn from(error: Error) -> Self {
        ProveError::LeanVm(error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeanVmConfig {
    /// How many threads leanVM's prover pool runs, 0 for one per physical
    /// core.
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
    /// verifying needs too, then proves and verifies one signature
    /// ([`Self::self_check`]): a prover that cannot run on this machine is
    /// reported here, at startup, rather than at the first aggregation duty.
    /// Takes about a second; call once.
    ///
    /// More threads than the machine has cores are lowered to the cores,
    /// with a warning: leanVM would oversubscribe them. Setup also picks the
    /// prover's CPU tier (since bindings v0.18.0), so a build that leaves
    /// some of this CPU unused says so on stderr here, not at the first
    /// proof.
    pub fn setup(config: LeanVmConfig) -> Result<Self, Error> {
        let rate = usize::from(config.log_inv_rate);
        if !(leanvm_prover::MIN_LOG_INV_RATE..=leanvm_prover::MAX_LOG_INV_RATE).contains(&rate) {
            return Err(Error::LogInvRate(config.log_inv_rate));
        }
        let cores = std::thread::available_parallelism().map_or(1, usize::from);
        let threads = threads_within(config.threads, cores);
        if threads != config.threads {
            tracing::warn!(
                asked = config.threads,
                cores,
                "More leanVM prover threads than cores; using one per core"
            );
        }
        let started = Instant::now();
        guarded("setup", || leanvm_prover::setup(threads))?;
        let backend = Self { log_inv_rate: rate };
        let setup_ms = started.elapsed().as_millis() as u64;
        let check = backend.self_check(1)?;
        tracing::info!(
            threads,
            log_inv_rate = config.log_inv_rate,
            leanvm_rev = LEANVM_REV,
            protocol_version = PROTOCOL_VERSION,
            setup_ms,
            self_check_prove_ms = check.prove.as_millis() as u64,
            self_check_verify_ms = check.verify.as_millis() as u64,
            "leanVM prover ready, in process"
        );
        Ok(backend)
    }

    /// Proves `signatures` leanXMSS signatures of a throwaway key, each over
    /// its own message at its own leaf, and checks that the proof verifies
    /// against those claims and against no others. The times are the prover's
    /// and the verifier's alone, without the signing.
    ///
    /// As many claims as a committee of `signatures` attesters gives, so the
    /// proving time is what one seat's aggregate of that size costs here.
    pub fn self_check(&self, signatures: usize) -> Result<SelfCheck, Error> {
        let input = self_check_input(signatures)?;
        self.prove_and_verify(input.statements, &input.signatures)
    }

    /// [`Self::self_check`] `rounds` times over one input, signed once: what
    /// proving costs on this machine round after round, the first paying for
    /// whatever the prover sets up on first use.
    pub fn measure(&self, signatures: usize, rounds: usize) -> Result<Vec<SelfCheck>, Error> {
        let input = self_check_input(signatures)?;
        (0..rounds)
            .map(|_| self.prove_and_verify(input.statements.clone(), &input.signatures))
            .collect()
    }

    fn prove_and_verify(
        &self,
        mut statements: Vec<AggregateStatement>,
        signed: &[Vec<Vec<u8>>],
    ) -> Result<SelfCheck, Error> {
        let started = Instant::now();
        let proof = self
            .prove(&statements, signed)
            .map_err(|err| Error::SelfCheck(format!("proving: {err}")))?;
        let prove = started.elapsed();
        let started = Instant::now();
        if !self.verify(&statements, &proof) {
            return Err(Error::SelfCheck("the proof it made does not verify".into()));
        }
        let verify = started.elapsed();
        // And against nothing else: a verifier that accepts every proof is
        // worse than one that accepts none.
        statements[0].message[31] ^= 1;
        if self.verify(&statements, &proof) {
            return Err(Error::SelfCheck(
                "the proof verifies against a claim it does not prove".into(),
            ));
        }
        Ok(SelfCheck {
            signatures: statements.len(),
            prove,
            verify,
            proof_bytes: proof.len(),
        })
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
                    let proof = guarded("decode", || AggregateProof::from_bytes(proof.as_ref()))?
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
        // A panic reads as a proof that does not verify: the bytes are a
        // peer's, and whatever they did to the verifier, they proved nothing.
        guarded("verify", || {
            AggregateProof::from_bytes(proof).is_some_and(|proof| proof.verify(&claims))
        })
        .unwrap_or(false)
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
        let (claims, proof) = guarded("aggregate", || {
            leanvm_prover::aggregate(
                children,
                raw_signatures,
                Vec::new(),
                None,
                OutputClaims::All,
                self.log_inv_rate,
            )
        })?
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

/// What [`LeanVmBackend::self_check`] proves: statements of one public key
/// each, and each statement's one signature, in the same order.
struct SelfCheckInput {
    statements: Vec<AggregateStatement>,
    signatures: Vec<Vec<Vec<u8>>>,
}

/// `signatures` statements of one signature each, by one throwaway key over
/// its first leaves, with their signatures as [`LeanVmBackend::prove`] takes
/// them.
///
/// One key rather than one per signature: a claim is a `(public key,
/// message)` pair, so the prover's work is the same, and a key's leaves share
/// a bottom tree that is built once. Its signatures are then independent and
/// made in parallel; the tree is built first, since a signature that had to
/// build it would do so with rayon from inside a rayon task.
fn self_check_input(signatures: usize) -> Result<SelfCheckInput, Error> {
    use rayon::prelude::*;
    let count = u32::try_from(signatures)
        .ok()
        .filter(|count| (1..=MAX_SELF_CHECK_SIGNATURES).contains(count))
        .ok_or_else(|| {
            Error::SelfCheck(format!(
                "cannot prove {signatures} signatures: 1 to {MAX_SELF_CHECK_SIGNATURES}"
            ))
        })?;
    let key = lean_xmss::range_key(&SELF_CHECK_SEED, 0, count - 1);
    key.prepare(0)
        .map_err(|err| Error::SelfCheck(format!("building the key: {err}")))?;
    let pubkey = key.public_key().to_bytes();
    let signed: Vec<(AggregateStatement, Vec<Vec<u8>>)> = (0..count)
        .into_par_iter()
        .map(|leaf| {
            let mut message: Message = [0x5c; 32];
            message[..4].copy_from_slice(&leaf.to_le_bytes());
            let signature = key
                .sign(&message, leaf)
                .map_err(|err| Error::SelfCheck(format!("signing: {err}")))?;
            let statement = AggregateStatement {
                pubkeys: vec![pubkey],
                leaf_index: u64::from(leaf),
                message,
            };
            Ok((statement, vec![signature.to_bytes()]))
        })
        .collect::<Result<_, Error>>()?;
    let (statements, signatures) = signed.into_iter().unzip();
    Ok(SelfCheckInput {
        statements,
        signatures,
    })
}

/// `asked` prover threads on a machine of `cores`: 0 (one per core) as it is,
/// and never more than the cores.
fn threads_within(asked: usize, cores: usize) -> usize {
    asked.min(cores)
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

    #[test]
    fn a_panic_inside_leanvm_is_an_error_not_an_unwind() {
        let caught = guarded("test", || -> u8 { panic!("boom {}", 7) });
        assert!(matches!(
            caught,
            Err(Error::Panicked { call: "test", reason }) if reason == "boom 7"
        ));
        assert_eq!(guarded("test", || 3).unwrap(), 3);
    }

    #[test]
    fn prover_threads_never_exceed_the_cores() {
        assert_eq!(threads_within(0, 8), 0);
        assert_eq!(threads_within(2, 8), 2);
        assert_eq!(threads_within(8, 8), 8);
        assert_eq!(threads_within(64, 8), 8);
    }

    /// The places that name the leanVM revision agree: this module's
    /// constant, the workspace manifest's three `rev`s, and the root
    /// `leanvm-revision` file, which the image build reads.
    #[test]
    fn the_leanvm_pin_is_the_same_everywhere() {
        let file = include_str!("../../../../../leanvm-revision").trim();
        assert_eq!(file, LEANVM_REV, "leanvm-revision");
        let manifest = include_str!("../../../../../Cargo.toml");
        for package in ["lean_vm", "claims", "lean_xmss"] {
            let named = format!("package = \"{package}\"");
            let line = manifest
                .lines()
                .find(|line| line.contains(&named))
                .unwrap_or_else(|| panic!("no {package} dependency in the workspace manifest"));
            assert!(line.contains(&format!("rev = \"{LEANVM_REV}\"")), "{line}");
        }
    }

    /// End to end on leanVM itself: `setup` proves and verifies its
    /// self-check, then two committees' proofs, merged, verify against their
    /// concatenated statements and nothing else, and bytes that are no proof
    /// verify against nothing.
    ///
    /// Ignored by a plain `cargo test`, which spends minutes on it
    /// unoptimized; `make test-consensus`, and so CI, runs it by name under
    /// `release-fast`, where it takes a second or two.
    #[test]
    #[ignore = "minutes unoptimized: `make test-consensus` runs it by name"]
    fn leanvm_proofs_merge_and_verify() {
        use crate::lean_xmss::range_key;
        let backend = LeanVmBackend::setup(LeanVmConfig::default()).unwrap();
        let check = backend.self_check(4).unwrap();
        assert_eq!(check.signatures, 4);
        assert!(check.proof_bytes > 0);
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
        // What a peer can send in a proof's place.
        assert!(!backend.verify(&both, &[0xff; 64]));
        assert!(!backend.verify(&both, &u64::MAX.to_le_bytes()));
        let mut flipped = merged.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(!backend.verify(&both, &flipped));
        // A signature made at another leaf than the statement's is refused
        // before leanVM sees it, since the proof would not attest the leaf.
        let wrong_leaf = [statement(&[c], 42, m2)];
        assert!(matches!(
            backend.prove(&wrong_leaf, &[vec![&sig_c]]),
            Err(ProveError::LeafIndex {
                expected: 42,
                found: 41,
                ..
            })
        ));
    }
}
