use ethlambda_prover_core::{Proof, ProverError, StfInput, StfProver, StfPublicValues};
use sp1_sdk::{
    MockProver, Prover, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
    include_elf,
};


const STATE_TRANSITION_ELF: &[u8] = include_elf!("zkvm_guest_sp1");
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
        let (pk, vk) = client.setup(STATE_TRANSITION_ELF).await;
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
        let bytes =
            bincode::serialize(&proof).map_err(|err| ProverError::Serialization(err.to_string()))?;
        Ok(Proof(bytes))
    }

    async fn verify(&self, proof: &Proof) -> Result<StfPublicValues, ProverError> {
        let mut sp1_proof: SP1ProofWithPublicValues = bincode::deserialize(proof.as_bytes())
            .map_err(|err| ProverError::Serialization(err.to_string()))?;

        self.client
            .verify(&sp1_proof, &self.vk)
            .await
            .map_err(|err| ProverError::Verify(err.to_string()))?;

        // The guest committed `StfPublicValues` via `io::commit`; read it back.
        Ok(sp1_proof.public_values.read::<StfPublicValues>())
    }
}
