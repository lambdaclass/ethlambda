pub use ethlambda_types::stf::{StfInput, StfPublicValues};

/// A serialized proof of a single state transition.
///
/// The bytes depend upon the specific zkVM being used, (SP1ProofWithPublicValues)
/// and carry both the proof and the committed public values, so
/// [`StfProver::verify`] can recover the [`StfPublicValues`] without re-running
/// the transition.
#[derive(Debug, Clone)]
pub struct Proof(pub Vec<u8>);

impl Proof {
    /// Borrow the raw proof bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Proof {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Proves and verifies state-transition executions on a zkVM backend.
///
/// The methods are `async` because real backends (SP1, RISC0, …) drive an
/// async prover client. This makes the trait non–object-safe, so consumers
/// select a backend by concrete type rather than `Box<dyn StfProver>`.
///
/// `async_fn_in_trait` is allowed deliberately: we don't constrain the returned
/// futures to `Send`, since backend prover clients don't all guarantee it.
#[allow(async_fn_in_trait)]
pub trait StfProver {
    /// Prove that applying the input's block to its pre-state is a valid
    /// transition, returning [`Proof`].
    async fn prove(&self, input: &StfInput) -> Result<Proof, ProverError>;

    /// Verify a proof and return the public values it commits to.
    async fn verify(&self, proof: &Proof) -> Result<StfPublicValues, ProverError>;
}

/// Errors raised while proving or verifying a state transition.
#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    /// The backend failed to produce a proof.
    #[error("proving failed: {0}")]
    Prove(String),
    /// The proof did not verify, or verification could not run.
    #[error("verification failed: {0}")]
    Verify(String),
    /// A proof or its public values could not be (de)serialized.
    #[error("proof (de)serialization failed: {0}")]
    Serialization(String),
}
