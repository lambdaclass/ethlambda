use std::time::{Duration, Instant};

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
/// async prover client.
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

    /// Execute the guest program, without generating the proof.
    async fn execute(&self, input: &StfInput) -> Result<StfPublicValues, ProverError>;

    /// [`Self::execute`] plus the wall-clock duration it took.
    async fn execute_timed(
        &self,
        input: &StfInput,
    ) -> Result<(StfPublicValues, Duration), ProverError> {
        let start = Instant::now();
        let public_values = self.execute(input).await?;
        Ok((public_values, start.elapsed()))
    }

    /// [`Self::prove`] plus the wall-clock duration it took.
    async fn prove_timed(&self, input: &StfInput) -> Result<(Proof, Duration), ProverError> {
        let start = Instant::now();
        let proof = self.prove(input).await?;
        Ok((proof, start.elapsed()))
    }

    /// [`Self::verify`] plus the wall-clock duration it took.
    async fn verify_timed(
        &self,
        proof: &Proof,
    ) -> Result<(StfPublicValues, Duration), ProverError> {
        let start = Instant::now();
        let public_values = self.verify(proof).await?;
        Ok((public_values, start.elapsed()))
    }
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
    /// The execution of the guest program failed.
    #[error("execution failed: {0}")]
    Execute(String),
}
