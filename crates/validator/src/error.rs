//! One error type for the crate.
//!
//! Variants are grouped by which layer raised them, because the recovery is
//! decided per layer: a beacon-node error means try the next node or skip the
//! duty, a keystore error at startup is fatal, and a signing error affects one
//! validator and never the rest. `Decode` sits with the beacon-node variants:
//! a response that fails to parse, or parses but makes no sense, is a symptom
//! of the node that sent it, not a separate layer. `Io` is deliberately
//! cross-cutting, since reading a keystore, a validator definitions file, or
//! any other config can fail this way; it carries the path so the caller does
//! not have to guess which file it was.

use ethlambda_types::beacon::primitives::BlsPubkey;

/// The EIP-2335 keystore schema version this client understands.
pub const EIP2335_KEYSTORE_VERSION: u64 = 4;

/// Why a beacon node request failed, classified at construction.
///
/// Failover and the duty loop need to tell a node that is down from one that
/// is merely slow. The concrete `reqwest::Error` is not carried in [`Error`]
/// because a test mock implementing `BeaconNodeApi` has to be able to
/// construct the same variant without ever holding a real HTTP error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeaconNodeFailure {
    /// The request outlived its timeout.
    Timeout,
    /// The connection could not be established.
    Connect,
    /// The request could not be built or sent.
    Request,
    /// The response body could not be read.
    Body,
}

impl BeaconNodeFailure {
    /// Classify a `reqwest` failure.
    pub fn classify(error: &reqwest::Error) -> Self {
        if error.is_timeout() {
            Self::Timeout
        } else if error.is_connect() {
            Self::Connect
        } else if error.is_body() || error.is_decode() {
            Self::Body
        } else {
            Self::Request
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("beacon node {url} failed ({failure:?}): {detail}")]
    BeaconNode {
        url: String,
        failure: BeaconNodeFailure,
        detail: String,
    },
    #[error("every configured beacon node failed; last error: {0}")]
    AllBeaconNodesFailed(String),
    #[error("beacon node returned {status}: {body}")]
    BeaconNodeStatus { status: u16, body: String },
    #[error("beacon node is syncing")]
    BeaconNodeSyncing,
    /// The slot's attestation work ran past the end of the slot and was
    /// abandoned.
    ///
    /// Distinct from the beacon-node failures above even though a hung node is
    /// the usual cause: those describe one request, this describes the duty as
    /// a whole giving up. Retryable, in the sense that the next slot's duty
    /// should still be attempted, which is all `is_retryable` governs; the
    /// abandoned attestation itself is never retried, by design.
    #[error("attestation duty for slot {slot} ran past the end of its slot")]
    AttestationDeadline { slot: u64 },
    /// The proposal guard refused to sign a block for this slot.
    ///
    /// Not a beacon-node failure and not retryable: the whole point of a
    /// refusal is that trying again produces the same answer. It is an error
    /// rather than a quiet `Ok` because a refusal means the duty loop asked for
    /// something it should not have, which is worth surfacing even though the
    /// block was correctly suppressed.
    #[error("refused to propose a block for slot {slot}: {reason}")]
    ProposalRefused { slot: u64, reason: String },
    #[error("beacon node returned an inconsistent response: {0}")]
    InconsistentResponse(String),
    #[error("malformed response: {0}")]
    Decode(String),

    #[error("keystore {path}: {reason}")]
    Keystore { path: String, reason: String },
    #[error("unsupported keystore version {0}, expected {EIP2335_KEYSTORE_VERSION}")]
    KeystoreVersion(u64),
    #[error("keystore password did not match the checksum")]
    KeystoreBadPassword,

    #[error("no signing key for validator {0:?}")]
    UnknownValidator(BlsPubkey),
    /// Not constructed today: the only `SigningMethod` is `LocalKeystore`,
    /// whose signing call cannot fail once a key has been resolved. Kept for
    /// the remote-signer variant `keys::store`'s module doc already commits
    /// to supporting, whose call to an external signer can fail in ways a
    /// local scalar multiplication cannot; remove this only if that plan is
    /// dropped.
    #[error("signing failed for {pubkey:?}: {reason}")]
    Signing { pubkey: BlsPubkey, reason: String },

    #[error("{path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

impl Error {
    /// Whether the duty loop should try again rather than give up.
    ///
    /// The distinction the loop needs every slot: a beacon node that is down,
    /// syncing or answering badly will likely answer correctly later, so the
    /// duty is skipped and retried. A bad keystore or an unknown validator will
    /// not fix itself, and retrying only hides it.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::BeaconNode { .. }
            | Self::AllBeaconNodesFailed(_)
            | Self::BeaconNodeStatus { .. }
            | Self::BeaconNodeSyncing
            | Self::InconsistentResponse(_)
            | Self::AttestationDeadline { .. }
            | Self::Decode(_) => true,
            // A refusal is deterministic: the guard will refuse the same slot
            // again, so retrying only repeats it.
            Self::ProposalRefused { .. }
            | Self::Keystore { .. }
            | Self::KeystoreVersion(_)
            | Self::KeystoreBadPassword
            | Self::UnknownValidator(_)
            | Self::Signing { .. }
            | Self::Io { .. } => false,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
