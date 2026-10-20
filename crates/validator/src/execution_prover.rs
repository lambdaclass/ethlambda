//! A mock prover of EIP-8440 execution chain proofs, for devnets
//! (`--execution-proofs.mock-prover`).
//!
//! No recursive guest program exists yet, so nothing produces real chain
//! proofs. Until one does, a devnet that wants to exercise their consumers
//! (a beacon node's `execution_proof` gossip and
//! `/eth/v1/beacon/execution_proofs`, or an execution client that serves state
//! only at proven blocks) needs something to put proofs on the wire. This duty
//! is that something. Once per slot, after the payload timeliness vote is due,
//! it reads the beacon node's head; if that block is new to it and the node
//! holds the block's execution payload envelope, it signs a
//! `SignedExecutionProof` whose proof bytes are what a mock zkVM emits (the
//! public values naming the proof's own blocks and chain, and no proof at
//! all), and submits it. A beacon node takes it only with
//! `--execution-proofs.mock`.
//!
//! The origin is the first head this client proved and never changes
//! afterwards: every later proof extends the same recursion, as a real
//! prover's would, so a consumer that trusts a checkpoint at or after that
//! origin accepts them all. Start the prover before the consumers.
//!
//! One proof type, [`MOCK_PROOF_TYPE`], and one prover: the first of this
//! client's validators the node reports active. The signature is the only
//! real cryptography here, and it is what the beacon node checks before it
//! reads the mock values.

use std::sync::{Arc, Mutex, MutexGuard};

use ethlambda_types::beacon::containers::execution_proof::{
    ExecutionProof, MockExecutionProof, SignedExecutionProof,
};
use ethlambda_types::beacon::primitives::{BlsPubkey, Root, ValidatorIndex};
use ethlambda_types::beacon::signing::compute_epoch_at_slot;
use libssz::SszEncode;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::beacon_node::BeaconNodeApi;
use crate::error::{Error, Result};
use crate::keys::ValidatorStore;
use crate::signing::SigningContext;

/// The proof type mock proofs claim: `1`, the provisional assignment of the
/// ethrex guest on OpenVM, which every node that takes execution proofs
/// supports.
pub const MOCK_PROOF_TYPE: u8 = 1;

pub struct ExecutionProverService<B> {
    beacon_node: Arc<B>,
    context: Arc<SigningContext>,
    /// A `std::sync::Mutex` for the reason the payload attestation service's
    /// is: every critical section is a read or a write with no await inside.
    state: Mutex<ProverState>,
}

#[derive(Default)]
struct ProverState {
    /// The first head proved: the origin of every proof after it.
    origin: Option<Root>,
    /// The last head proved, so a head that stays put costs no request.
    proved: Option<Root>,
    /// The validator that signs, resolved once from the node's registry.
    prover: Option<(BlsPubkey, ValidatorIndex)>,
}

impl<B: BeaconNodeApi> ExecutionProverService<B> {
    pub fn new(beacon_node: Arc<B>, context: Arc<SigningContext>) -> Self {
        Self {
            beacon_node,
            context,
            state: Mutex::new(ProverState::default()),
        }
    }

    /// The bytes of a mock proof claiming `proof`'s public input on
    /// `chain_id`: the SSZ `MockProof` a mock zkVM emits.
    pub fn mock_proof_data(proof: &ExecutionProof, chain_id: u64) -> Vec<u8> {
        MockExecutionProof {
            public_values: proof
                .public_input(chain_id)
                .to_ssz()
                .try_into()
                .expect("a public input is far below the proof size bound"),
            proof: b"mock".to_vec().try_into().expect("four bytes fit"),
        }
        .to_ssz()
    }

    /// The origin every proof so far named, if one was proved.
    pub fn origin(&self) -> Option<Root> {
        self.lock().origin
    }

    /// Prove the beacon node's head if it is new to this client and the node
    /// holds its payload envelope. Returns the proof submitted, if any.
    ///
    /// Safe to call every slot: a head already proved, a head without a
    /// payload yet and a client with no active validator all return `None`
    /// without signing anything.
    pub async fn prove_head(
        &self,
        store: &RwLock<ValidatorStore>,
    ) -> Result<Option<SignedExecutionProof>> {
        let head = self.beacon_node.head_block_root().await?;
        if self.lock().proved == Some(head) {
            return Ok(None);
        }
        let Some(slot) = self.beacon_node.block_slot(head).await? else {
            warn!(%head, "The beacon node reported a head it does not serve; not proving it");
            return Ok(None);
        };
        if !self
            .beacon_node
            .has_execution_payload_envelope(head)
            .await?
        {
            info!(%slot, %head, "The head has no payload envelope yet; not proving it");
            return Ok(None);
        }
        let Some((pubkey, validator_index)) = self.prover(store).await? else {
            warn!("No active validator to sign mock execution proofs with");
            return Ok(None);
        };

        let origin = *self.lock().origin.get_or_insert(head);
        let chain_id = self.context.config.deposit_chain_id;
        let mut message = ExecutionProof {
            proof_data: Default::default(),
            proof_type: MOCK_PROOF_TYPE,
            origin_block_root: origin,
            head_block_root: head,
        };
        message.proof_data = Self::mock_proof_data(&message, chain_id)
            .try_into()
            .map_err(|_| Error::InconsistentResponse("mock proof over the size bound".into()))?;
        let signature = {
            let _timing = crate::metrics::time_signing();
            let store = store.read().await;
            self.context.sign_execution_proof(
                &store,
                &pubkey,
                &message,
                compute_epoch_at_slot(slot),
            )?
        };
        let signed = SignedExecutionProof {
            message,
            validator_index,
            signature,
        };

        let accepted = self
            .beacon_node
            .submit_execution_proofs(std::slice::from_ref(&signed))
            .await?;
        // Recorded whatever the node said: a refusal is not fixed by sending
        // the same proof again next slot.
        self.lock().proved = Some(head);
        if accepted == 0 {
            warn!(%slot, %head, "The beacon node refused the mock execution proof");
            return Ok(None);
        }
        info!(
            %slot,
            %head,
            %origin,
            validator = validator_index,
            "Submitted a mock execution proof"
        );
        crate::metrics::inc_execution_proofs_published(accepted as u64);
        Ok(Some(signed))
    }

    /// The validator that signs: the first of this client's keys the node
    /// reports active, resolved once.
    async fn prover(
        &self,
        store: &RwLock<ValidatorStore>,
    ) -> Result<Option<(BlsPubkey, ValidatorIndex)>> {
        if let Some(prover) = self.lock().prover {
            return Ok(Some(prover));
        }
        let pubkeys = store.read().await.pubkeys();
        if pubkeys.is_empty() {
            return Ok(None);
        }
        let entries = self.beacon_node.validator_indices(&pubkeys).await?;
        let chosen = entries
            .iter()
            .find(|entry| entry.status.starts_with("active"))
            .map(|entry| (entry.pubkey, entry.index));
        if let Some(prover) = chosen {
            self.lock().prover = Some(prover);
        }
        Ok(chosen)
    }

    fn lock(&self) -> MutexGuard<'_, ProverState> {
        self.state.lock().expect("prover state lock poisoned")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_node::ValidatorEntry;
    use crate::beacon_node::mock::MockBeaconNode;
    use crate::keys::ValidatorStore;
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::fork::ForkName;
    use libssz::SszDecode as _;

    const HEAD: Root = Root::repeat_byte(0x11);

    fn context() -> Arc<SigningContext> {
        Arc::new(SigningContext {
            config: Config::mainnet().with_fork_epoch(ForkName::Gloas, 0),
            genesis_validators_root: Root::ZERO,
        })
    }

    /// A store with one key, and the mock node reporting it active.
    fn keyed() -> (Arc<RwLock<ValidatorStore>>, ValidatorEntry) {
        let mut store = ValidatorStore::new();
        let pubkey = store
            .insert_secret("test", &[7u8; 32])
            .expect("a valid secret");
        let entry = ValidatorEntry {
            index: 5,
            pubkey,
            status: "active_ongoing".to_string(),
        };
        (Arc::new(RwLock::new(store)), entry)
    }

    #[tokio::test]
    async fn proves_a_new_full_head_once_and_keeps_its_origin() {
        let (store, entry) = keyed();
        let mut node = MockBeaconNode::default()
            .with_head_root(HEAD)
            .with_head_slot(9)
            .with_head_envelope();
        node.validators = vec![entry.clone()];
        let node = Arc::new(node);
        let service = ExecutionProverService::new(node.clone(), context());

        let proved = service
            .prove_head(&store)
            .await
            .expect("proved")
            .expect("a proof");
        assert_eq!(proved.validator_index, 5);
        assert_eq!(proved.message.head_block_root, HEAD);
        assert_eq!(
            proved.message.origin_block_root, HEAD,
            "a recursion starts here"
        );
        assert_eq!(proved.message.proof_type, MOCK_PROOF_TYPE);
        let mock = MockExecutionProof::from_ssz_bytes(&proved.message.proof_data).expect("mock");
        assert_eq!(
            mock.public_values.as_ref(),
            proved
                .message
                .public_input(Config::mainnet().deposit_chain_id)
                .to_ssz()
                .as_slice()
        );
        assert_eq!(node.submitted_execution_proofs().len(), 1);

        // The same head again costs nothing.
        assert!(service.prove_head(&store).await.expect("ok").is_none());
        assert_eq!(node.submitted_execution_proofs().len(), 1);
        assert_eq!(service.origin(), Some(HEAD));
    }

    #[tokio::test]
    async fn a_head_without_a_payload_envelope_is_not_proved() {
        let (store, entry) = keyed();
        let mut node = MockBeaconNode::default()
            .with_head_root(HEAD)
            .with_head_slot(9);
        node.validators = vec![entry];
        let node = Arc::new(node);
        let service = ExecutionProverService::new(node.clone(), context());
        assert!(service.prove_head(&store).await.expect("ok").is_none());
        assert!(node.submitted_execution_proofs().is_empty());
        assert_eq!(service.origin(), None);
    }
}
