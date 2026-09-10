use ethlambda_prover_core::{Proof, ProverError, StfInput, StfProver, StfPublicValues};
use sp1_sdk::{
    Elf, MockProver, ProveRequest, Prover, ProvingKey, SP1ProofWithPublicValues, SP1ProvingKey,
    SP1Stdin, SP1VerifyingKey, include_elf,
};

const STATE_TRANSITION_ELF: Elf = include_elf!("zkvm_guest_sp1");
const CYCLE_LIMIT: u64 = 10_000_000;

/// SP1 prover: proves the STF guest and verifies its proofs.
///
/// The proving/verifying keys are derived once via [`Sp1Prover::new`] because
/// `setup` is expensive and must not run per proof.
/// [TODO!]: check if using Lazylock might be better
pub struct Sp1Prover {
    client: MockProver,
    pk: SP1ProvingKey,
    vk: SP1VerifyingKey,
}

impl Sp1Prover {
    /// Build the prover once, caching the proving/verifying keys and
    /// currently uses the MockProver.
    pub async fn new() -> Self {
        let client = MockProver::new().await;
        // let client = ProverClient::builder().cpu().await;
        // `setup` returns only the proving key (fallible); the verifying key is
        // derived from it.
        let pk = client
            .setup(STATE_TRANSITION_ELF)
            .await
            .expect("failed to set up SP1 proving key");
        let vk = pk.verifying_key().clone();
        Self { client, pk, vk }
    }
}

impl StfProver for Sp1Prover {
    async fn prove(&self, input: &StfInput) -> Result<Proof, ProverError> {
        let mut stdin = SP1Stdin::new();
        stdin.write(input);

        // use `.groth16()` instead of `.compressed()` for real proving and verification
        let proof = self
            .client
            .prove(&self.pk, stdin)
            .compressed()
            .cycle_limit(CYCLE_LIMIT)
            .await
            .map_err(|err| ProverError::Prove(err.to_string()))?;

        // Store the whole proof (including public values) so `verify` can
        // recover the committed `StfPublicValues`.
        let bytes = bincode::serialize(&proof)
            .map_err(|err| ProverError::Serialization(err.to_string()))?;
        Ok(Proof(bytes))
    }

    async fn verify(&self, proof: &Proof) -> Result<StfPublicValues, ProverError> {
        let mut sp1_proof: SP1ProofWithPublicValues = bincode::deserialize(proof.as_bytes())
            .map_err(|err| ProverError::Serialization(err.to_string()))?;

        // `verify` is synchronous in this SDK and takes an optional status code.
        self.client
            .verify(&sp1_proof, &self.vk, None)
            .map_err(|err| ProverError::Verify(err.to_string()))?;

        // The guest committed `StfPublicValues` via `io::commit`; read it back.
        Ok(sp1_proof.public_values.read::<StfPublicValues>())
    }

    async fn execute(&self, input: &StfInput) -> Result<StfPublicValues, ProverError> {
        let mut stdin = SP1Stdin::new();
        stdin.write(input);

        // Runs the guest in the SP1 executor without proving; the future yields
        // `(SP1PublicValues, ExecutionReport)`. We ignore the report for now.
        let (mut public_values, _report) = self
            .client
            .execute(STATE_TRANSITION_ELF, stdin)
            .cycle_limit(CYCLE_LIMIT)
            .await
            .map_err(|err| ProverError::Execute(err.to_string()))?;

        // The guest committed `StfPublicValues` via `io::commit`; read it back.
        Ok(public_values.read::<StfPublicValues>())
    }
}
