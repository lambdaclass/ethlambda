//! Attestation proofs from a `leanvm-sidecar` process, over its Unix socket
//! (protocol version 1, `bins/leanvm-sidecar/README.md` in the leanVM
//! repository).
//!
//! The PQ devnet does not run the specification's reference concatenation:
//! its clients prove with leanVM, through this sidecar. The wire protocol is
//! leanVM's own client crate at the revision the workspace pins
//! ([`LEANVM_REV`]). The sidecar itself is started outside this process, as
//! for Lighthouse, and may be built from another revision: the hello is
//! checked for this client's protocol version and verifier tag, and nothing
//! else on the wire detects a mismatch. Proofs only have to verify with the
//! other clients' verifiers, so which revision a devnet proves with is the
//! devnet's choice, within that tag.
//!
//! The mapping from the specification's statements is Lighthouse's, so the
//! two clients' proofs verify against each other:
//!
//! - A leanVM proof attests `(public key, message)` claims. A statement list
//!   flattens to the sorted, deduplicated list of its pairs (the verifier only
//!   accepts a claim list strictly sorted by the 64 bytes `pubkey || message`).
//! - **The leaf index is not part of a claim** (leanEthereum/leanVM#787), so
//!   [`SidecarBackend::verify`] shows each key signed the message at *some*
//!   leaf, not at the statement's. [`SidecarBackend::prove`] refuses
//!   signatures made at another leaf, since it sees them.
//! - The empty proof stands for "nothing to prove" (the sidecar refuses to
//!   prove zero claims), and verifies only against no claims.
//! - A merge folds the children [`MAX_CHILDREN_PER_AGGREGATE`] at a time,
//!   round after round, until one proof remains.
//!
//! Connections are reopened after a failure. One is for proving, where
//! requests queue in the sidecar. The others, [`SidecarConfig::verify_connections`]
//! of them, are for verifying, which the sidecar answers without waiting for
//! proofs in progress: it serves each connection on a thread of its own and
//! verifies there, so verifications on different connections run at once.
//! A verification takes a free connection and waits on one only when every
//! one is busy, so the node's gossip checks, imports and block production do
//! not queue behind each other's round trips.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use leanvm_claims::{AggregateClaims, OutputClaims};
use leanvm_lean_xmss::{LeanXmssPublicKey, LeanXmssSignature};
use leanvm_sidecar::{Client, SidecarError};

use super::{AggregateStatement, ProveError};
use crate::lean_xmss::{self, Message, PUBKEY_SIZE, SIGNATURE_SIZE};

/// The most children one aggregate request takes.
pub const MAX_CHILDREN_PER_AGGREGATE: usize = 16;

/// The leanVM revision the workspace's sidecar client is pinned to (bindings
/// v0.15.0). A sidecar from another revision is accepted when its hello
/// carries this client's protocol version and verifier tag.
pub const LEANVM_REV: &str = "c5ee9d239e42d0bc8113eb4aee3e2cae5faf1764";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sidecar connection: {0}")]
    Io(#[from] std::io::Error),
    #[error("sidecar: {0}")]
    Sidecar(String),
    #[error("a proof backend is already installed")]
    AlreadyInstalled,
    #[error("the sidecar proved {found} claims, {expected} were asked")]
    ClaimsMismatch { expected: usize, found: usize },
    #[error("child {0} has claims and an empty proof, or a proof and no claims")]
    MalformedChild(usize),
}

impl From<SidecarError> for Error {
    fn from(error: SidecarError) -> Self {
        match error {
            SidecarError::Io(error) => Error::Io(error),
            other => Error::Sidecar(format!("{other:?}")),
        }
    }
}

impl From<Error> for ProveError {
    fn from(error: Error) -> Self {
        ProveError::Sidecar(error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarConfig {
    /// The Unix socket `leanvm-sidecar --socket` listens on.
    pub socket: PathBuf,
    /// `log_inv_rate` of the proofs requested, 1 to 4: a higher rate gives
    /// smaller proofs that take longer to make. A proof verifies whatever rate
    /// it was made at.
    pub log_inv_rate: u8,
    /// How long one prove or merge request may wait on the sidecar, queueing
    /// behind others included.
    pub prove_timeout: Duration,
    /// How long one verify request may wait on the sidecar.
    pub verify_timeout: Duration,
    /// How many connections verify at once, at least one. The sidecar serves
    /// at most 16 connections, the proving one among them.
    pub verify_connections: usize,
}

/// How many verifications run at once by default: enough that a burst of
/// gossip aggregates does not hold up a block's proof, few enough to leave
/// the prover its cores and the sidecar its connection limit.
pub const DEFAULT_VERIFY_CONNECTIONS: usize = 4;

impl SidecarConfig {
    /// Lighthouse's defaults, and [`DEFAULT_VERIFY_CONNECTIONS`].
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            log_inv_rate: 2,
            prove_timeout: Duration::from_secs(300),
            verify_timeout: Duration::from_secs(30),
            verify_connections: DEFAULT_VERIFY_CONNECTIONS,
        }
    }
}

pub struct SidecarBackend {
    config: SidecarConfig,
    prove_connection: Mutex<Option<Client>>,
    /// Never empty. Each opened on first use, but for the first.
    verify_connections: Vec<Mutex<Option<Client>>>,
    /// Where the next verification starts looking for a free connection, so
    /// the waits spread over all of them when every one is busy.
    next_verify: AtomicUsize,
}

impl SidecarBackend {
    /// Opens the proving connection and the first verifying one now, checking
    /// each hello (magic, protocol version, verifier tag), so a missing or
    /// incompatible sidecar is reported at startup. The other verifying
    /// connections open on first use.
    pub fn connect(config: SidecarConfig) -> Result<Self, Error> {
        let prove_connection = open(&config, config.prove_timeout)?;
        let first_verify = open(&config, config.verify_timeout)?;
        tracing::info!(
            socket = %config.socket.display(),
            prover = prove_connection.prover(),
            client_leanvm_rev = LEANVM_REV,
            verify_connections = config.verify_connections.max(1),
            "Connected to the leanVM prover sidecar"
        );
        let verify_connections = std::iter::once(Some(first_verify))
            .chain(std::iter::repeat_with(|| None))
            .take(config.verify_connections.max(1))
            .map(Mutex::new)
            .collect();
        Ok(Self {
            config,
            prove_connection: Mutex::new(Some(prove_connection)),
            verify_connections,
            next_verify: AtomicUsize::new(0),
        })
    }

    /// A free verifying connection, or, when every one is busy, the next one
    /// in turn once it frees.
    fn verify_connection(&self) -> MutexGuard<'_, Option<Client>> {
        let count = self.verify_connections.len();
        let start = self.next_verify.fetch_add(1, Ordering::Relaxed) % count;
        let in_turn = (0..count).map(|offset| &self.verify_connections[(start + offset) % count]);
        for connection in in_turn {
            match connection.try_lock() {
                Ok(guard) => return guard,
                Err(TryLockError::Poisoned(poisoned)) => return poisoned.into_inner(),
                Err(TryLockError::WouldBlock) => {}
            }
        }
        lock(&self.verify_connections[start])
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
        Ok(self.aggregate(&[], &raw_signatures, &expected)?)
    }

    pub(super) fn merge<S: AsRef<[AggregateStatement]>, P: AsRef<[u8]>>(
        &self,
        children: &[(S, P)],
    ) -> Result<Vec<u8>, ProveError> {
        let mut level: Vec<(AggregateClaims, Vec<u8>)> = Vec::with_capacity(children.len());
        for (index, (statements, proof)) in children.iter().enumerate() {
            let claims = statements_to_claims(statements.as_ref());
            match (claims.lean_xmss.is_empty(), proof.as_ref().is_empty()) {
                (true, true) => {}
                (false, false) => level.push((claims, proof.as_ref().to_vec())),
                _ => return Err(Error::MalformedChild(index).into()),
            }
        }
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(MAX_CHILDREN_PER_AGGREGATE));
            for chunk in level.chunks(MAX_CHILDREN_PER_AGGREGATE) {
                if let [only] = chunk {
                    next.push(only.clone());
                    continue;
                }
                let expected = union(chunk);
                let proof = self.aggregate(chunk, &[], &expected)?;
                next.push((expected, proof));
            }
            level = next;
        }
        Ok(level.pop().map(|(_, proof)| proof).unwrap_or_default())
    }

    pub(super) fn verify(
        &self,
        statements: &[AggregateStatement],
        proof: &[u8],
    ) -> Result<bool, Error> {
        let claims = statements_to_claims(statements);
        if claims.lean_xmss.is_empty() || proof.is_empty() {
            return Ok(claims.lean_xmss.is_empty() && proof.is_empty());
        }
        with_connection(
            &self.config,
            self.verify_connection(),
            self.config.verify_timeout,
            |client| client.verify(&claims, proof),
        )
    }

    /// One aggregate request on the proving connection. Checks the sidecar
    /// proved exactly `expected`.
    fn aggregate(
        &self,
        children: &[(AggregateClaims, Vec<u8>)],
        raw_signatures: &[(LeanXmssPublicKey, Message, LeanXmssSignature)],
        expected: &AggregateClaims,
    ) -> Result<Vec<u8>, Error> {
        let started = Instant::now();
        let (claims, proof) = with_connection(
            &self.config,
            lock(&self.prove_connection),
            self.config.prove_timeout,
            |client| {
                client.aggregate(
                    children,
                    raw_signatures,
                    &[],
                    &[],
                    OutputClaims::All,
                    usize::from(self.config.log_inv_rate),
                )
            },
        )?;
        if claims != *expected {
            return Err(Error::ClaimsMismatch {
                expected: expected.num_signature_claims(),
                found: claims.num_signature_claims(),
            });
        }
        tracing::debug!(
            children = children.len(),
            signatures = raw_signatures.len(),
            claims = claims.num_signature_claims(),
            proof_bytes = proof.len(),
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
fn union(children: &[(AggregateClaims, Vec<u8>)]) -> AggregateClaims {
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

fn open(config: &SidecarConfig, timeout: Duration) -> Result<Client, Error> {
    let client = Client::connect(&config.socket)?;
    client.set_timeout(Some(timeout))?;
    Ok(client)
}

/// `connection`'s lock. A panic while it was held leaves the connection as
/// it was, which the next call reuses or reopens like any other.
fn lock(connection: &Mutex<Option<Client>>) -> MutexGuard<'_, Option<Client>> {
    connection
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Runs `call` on the connection in `slot`, held for the whole call, opening
/// it first if needed. A connection that fails is dropped, as the protocol
/// requires after anything but a rejection; if a reused one failed other than
/// by timing out, the sidecar may have restarted, so this reconnects and
/// tries once more.
fn with_connection<T>(
    config: &SidecarConfig,
    mut slot: MutexGuard<'_, Option<Client>>,
    timeout: Duration,
    mut call: impl FnMut(&mut Client) -> Result<T, SidecarError>,
) -> Result<T, Error> {
    let mut reused = slot.is_some();
    loop {
        let client = match slot.as_mut() {
            Some(client) => client,
            None => slot.insert(open(config, timeout)?),
        };
        match call(client) {
            Ok(value) => return Ok(value),
            Err(SidecarError::Rejected(rejection, message)) => {
                return Err(Error::Sidecar(format!("{rejection:?}: {message}")));
            }
            Err(SidecarError::Io(error))
                if reused
                    && !matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
            {
                *slot = None;
                reused = false;
            }
            Err(error) => {
                *slot = None;
                return Err(error.into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A backend with `count` verifying connections, none opened.
    fn unconnected(count: usize) -> SidecarBackend {
        SidecarBackend {
            config: SidecarConfig::new("/nonexistent"),
            prove_connection: Mutex::new(None),
            verify_connections: (0..count).map(|_| Mutex::new(None)).collect(),
            next_verify: AtomicUsize::new(0),
        }
    }

    /// A verification takes a free connection rather than wait on a busy
    /// one, so verifications run side by side.
    #[test]
    fn a_verification_takes_a_free_connection_past_busy_ones() {
        let backend = unconnected(3);
        let first = backend.verify_connection();
        let second = backend.verify_connection();
        let third = backend.verify_connection();
        // Three at once, none waiting: each took its own connection.
        assert!(
            backend
                .verify_connections
                .iter()
                .all(|c| c.try_lock().is_err())
        );
        drop(second);
        // With two busy, the next one finds the free one wherever the
        // rotation starts.
        let again = backend.verify_connection();
        assert!(
            backend
                .verify_connections
                .iter()
                .all(|c| c.try_lock().is_err())
        );
        drop((first, third, again));
    }

    #[test]
    fn at_least_one_connection_verifies() {
        let config = SidecarConfig {
            verify_connections: 0,
            ..SidecarConfig::new("/nonexistent")
        };
        assert_eq!(config.verify_connections.max(1), 1);
        assert_eq!(
            SidecarConfig::new("/x").verify_connections,
            DEFAULT_VERIFY_CONNECTIONS
        );
    }

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
}
