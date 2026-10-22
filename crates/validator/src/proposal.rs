//! Producing, signing and publishing this slot's block.
//!
//! The attestation path's counterpart, and deliberately shaped like it. What
//! differs is the cost of each step and therefore where the checks sit.
//!
//! # Three signatures, one slot
//!
//! A proposal needs two signatures from this client and gets a third thing
//! back from the beacon node in between:
//!
//! 1. The **RANDAO reveal** for the slot's epoch, signed first because the node
//!    cannot build a body without it. It is not slashable and is not guarded.
//! 2. The **block**, built by the beacon node around that reveal. This client
//!    never chooses a block's contents; it asks for one and checks that what
//!    came back is the one it asked for.
//! 3. The **block signature**, which is slashable and is guarded.
//!
//! # Why the guard is consulted twice
//!
//! Once before asking for a block, once before signing it.
//!
//! The early check is not about safety, it is about cost. Producing a block
//! makes the beacon node drive an execution-layer payload build, which is the
//! most expensive thing this client can ask of it. Discovering only afterwards
//! that the slot was already proposed wastes that for nothing.
//!
//! The check before signing is the one that matters, and it records. Recording
//! at signing time rather than after publication is what makes the duty loop's
//! deadline safe: a proposal abandoned between signing and publishing cannot be
//! re-signed, because the guard already counts that slot as proposed.
//!
//! # Do not retry this call within a slot
//!
//! For the same reason [`crate::attestation::AttestationService::attest`] must
//! not be: a second call asks the node for a second block, which will differ
//! from the first because the node has packed whatever arrived in between, and
//! two distinct blocks for one slot from one validator is a slashable proposer
//! offence. The guard refuses it, so a retry is merely useless rather than
//! dangerous, but the caller should not be relying on the guard for that.

use std::sync::Arc;

use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{ExecutionAddress, HashTreeRoot as _, Slot};
use ethlambda_types::beacon::signing::compute_epoch_at_slot;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::beacon_node::dto::{ProposerDutyDto, parse_pubkey};
use crate::beacon_node::{BeaconNodeApi, BlockRequest, Published, validate_produced_block};
use crate::error::{Error, Result};
use crate::keys::ValidatorStore;
use crate::proposal_guard::ProposalGuard;
use crate::proposer_settings::ProposerSettings;
use crate::signing::SigningContext;

pub struct ProposalService<B> {
    beacon_node: Arc<B>,
    context: Arc<SigningContext>,
    /// Each validator's graffiti, sent with its block request, and fee
    /// recipient.
    ///
    /// The fee recipient is held only to check what comes back. The beacon node
    /// is the one that builds the payload, and the specification is explicit
    /// that it need not honour the preparation it was sent.
    settings: Arc<ProposerSettings>,
    /// What this process has already proposed, per validator.
    ///
    /// A `std::sync::Mutex` for the reason [`crate::attestation`]'s is: the
    /// critical section is a lookup and an insert with no await inside it, so
    /// an async mutex would buy nothing and cost a scheduling point.
    ///
    /// Not slashing protection. See [`ProposalGuard`].
    guard: std::sync::Mutex<ProposalGuard>,
}

impl<B: BeaconNodeApi> ProposalService<B> {
    pub fn new(
        beacon_node: Arc<B>,
        context: Arc<SigningContext>,
        settings: Arc<ProposerSettings>,
    ) -> Self {
        Self {
            beacon_node,
            context,
            settings,
            guard: std::sync::Mutex::new(ProposalGuard::new()),
        }
    }

    /// Compare the produced block's fee recipient against what was asked for,
    /// and complain loudly if they differ.
    ///
    /// # Why this warns instead of refusing
    ///
    /// The specification requires the check and leaves the response open: a
    /// client "should confirm that it finds the fee recipient within the block
    /// acceptable before signing it". Both answers cost the operator money, and
    /// they are not the same amount.
    ///
    /// Refusing loses the consensus-layer reward *and* the execution-layer one,
    /// and costs the network a slot. Signing loses only the execution-layer
    /// reward, which was already going elsewhere the moment the node built the
    /// payload. So signing is the cheaper of the two for the operator and
    /// strictly better for the network, and the thing that actually fixes it is
    /// the operator noticing.
    ///
    /// Hence `error!` rather than `warn!`, and a counter beside it: this should
    /// never happen, and when it does it is a misconfigured or untrustworthy
    /// beacon node paying someone else, every time this validator proposes.
    ///
    /// With no configured address there is nothing to compare against and this
    /// says nothing, which is the same silence as a matching one; the startup
    /// warning is where that case is reported.
    fn check_fee_recipient(
        produced: &crate::beacon_node::block_contents::ProducedBlock,
        expected: Option<ExecutionAddress>,
        slot: Slot,
    ) {
        let Some(expected) = expected else {
            return;
        };
        let actual = produced.block().body.execution_payload.fee_recipient;
        if actual != expected {
            tracing::error!(
                %slot,
                expected = %crate::beacon_node::dto::encode_hex(&expected.0),
                actual = %crate::beacon_node::dto::encode_hex(&actual.0),
                "Block pays its execution-layer rewards to an address this client did not ask \
                 for; signing it anyway, since refusing would also forfeit the consensus reward \
                 and cost the network a slot. Check this beacon node's proposer preparation. A \
                 fee recipient changed through the keymanager API this epoch reaches the node \
                 only at the next one."
            );
            crate::metrics::inc_fee_recipient_mismatches();
        }
    }

    /// Produce, sign and publish the block for `slot`.
    ///
    /// Returns what became of it, which is not always a clean success: see
    /// [`Published`].
    pub async fn propose(
        &self,
        slot: Slot,
        duty: &ProposerDutyDto,
        store: &RwLock<ValidatorStore>,
    ) -> Result<Published> {
        let pubkey = parse_pubkey(&duty.pubkey)?;
        let epoch = compute_epoch_at_slot(slot);

        // Before paying for a block, not after. See the module doc.
        //
        // A poisoned lock is treated as a refusal rather than unwrapped: the
        // lock is poisoned only by a panic while it is held, nothing inside it
        // can panic, and a crash in the duty path would be a worse outcome than
        // a skipped proposal.
        match self.guard.lock() {
            Ok(guard) => {
                if let Err(refusal) = guard.check(&pubkey, slot) {
                    warn!(
                        %slot,
                        validator = duty.validator_index,
                        %refusal,
                        "Refusing to propose: this process already proposed this slot"
                    );
                    crate::metrics::inc_blocks_refused();
                    return Err(Error::ProposalRefused {
                        slot,
                        reason: refusal.to_string(),
                    });
                }
            }
            Err(err) => {
                warn!(%slot, %err, "Proposal guard is poisoned; refusing to propose");
                crate::metrics::inc_blocks_refused();
                return Err(Error::ProposalRefused {
                    slot,
                    reason: "the proposal guard is poisoned".to_string(),
                });
            }
        }

        // Scoped away from every await, the way the attestation path's read
        // guard is, and for the reason spelled out there: a write-preferring
        // lock lets one queued keymanager writer block every reader behind it,
        // so a guard held across the block production round trip below would
        // put the whole duty path behind it.
        let randao_reveal = {
            let store = store.read().await;
            self.context.sign_randao(&store, &pubkey, epoch)?
        };

        // Both read once, before the block is asked for, so the check below
        // compares against the address in force when the request went out.
        let graffiti = self.settings.graffiti(&pubkey);
        let fee_recipient = self.settings.fee_recipient(&pubkey);
        let request = BlockRequest {
            slot,
            proposer_index: duty.validator_index,
            randao_reveal,
            graffiti,
        };
        let produced = self.beacon_node.produce_block(&request).await?;

        // Checked again here, having already been checked by the
        // implementation this call went through. Not redundant, and the
        // attestation path does the same for the same reason: the trait is
        // public, so this is the last point at which a wrong answer from an
        // implementation that failed to honour its contract can be stopped
        // before it becomes a signature.
        //
        // It matters more here than it reads. The guard records the *requested*
        // slot while the signature covers the *produced* header's slot. If
        // those ever diverged and both fell in one epoch, the domain would be
        // identical and the result would be a valid, unguarded second block for
        // a slot already proposed.
        validate_produced_block(&request, &produced)?;

        // The node's fork and this client's must agree, or the signature is
        // computed under a fork version the network does not accept.
        //
        // The two are separate facts. The block was decoded, and will be
        // published, under the fork the node named in its response header. The
        // signing domain comes from this client's own fork schedule, fetched
        // from `/config/spec` at startup. They normally agree because they came
        // from the same place; when they do not, one of them is wrong about
        // where a fork boundary sits, and signing anyway produces a block that
        // is rejected for a reason nothing in the logs would explain.
        let expected = self.context.config.fork_at_epoch(epoch);
        if produced.fork != expected {
            return Err(Error::InconsistentResponse(format!(
                "node produced a {} block for slot {slot}, but this client's fork schedule puts \
                 epoch {epoch} in {}; signing would use the wrong fork version",
                produced.fork.as_str(),
                expected.as_str()
            )));
        }

        Self::check_fee_recipient(&produced, fee_recipient, slot);

        let fork = produced.fork;
        info!(
            %slot,
            validator = duty.validator_index,
            fork = fork.as_str(),
            blobs = produced.blob_count(),
            "Block produced; signing"
        );

        // The root is taken from the decoded container, never from anything
        // reassembled here, and it is taken once: the same value is what the
        // guard's slot is recorded against and what the signature covers.
        let block_root = produced.block().hash_tree_root();

        let signature = {
            let store = store.read().await;

            // The check that matters, and the one that records. Everything
            // after this point may be abandoned without risk, because the
            // guard already counts this slot as proposed.
            match self.guard.lock() {
                Ok(mut guard) => guard.check_and_record(&pubkey, slot).map_err(|refusal| {
                    crate::metrics::inc_blocks_refused();
                    Error::ProposalRefused {
                        slot,
                        reason: refusal.to_string(),
                    }
                })?,
                Err(err) => {
                    warn!(%slot, %err, "Proposal guard is poisoned; refusing to sign");
                    crate::metrics::inc_blocks_refused();
                    return Err(Error::ProposalRefused {
                        slot,
                        reason: "the proposal guard is poisoned".to_string(),
                    });
                }
            }

            self.context.sign_block(&store, &pubkey, block_root, slot)?
        };

        let body = produced.into_signed_ssz(signature);
        let published = self
            .publish(fork, &body, slot, duty.validator_index)
            .await?;
        crate::metrics::inc_blocks_proposed();
        Ok(published)
    }

    /// Send the signed body and report what the node made of it.
    ///
    /// Split out so the 202 case has one place to be explained rather than
    /// being an arm of an already long function.
    async fn publish(
        &self,
        fork: ForkName,
        body: &[u8],
        slot: Slot,
        validator: u64,
    ) -> Result<Published> {
        let published = self.beacon_node.publish_block(fork, body).await?;
        match published {
            Published::Imported => {
                info!(%slot, validator, bytes = body.len(), "Block published");
            }
            // Not an error, and not silence either. The block reached the
            // network, so the proposal may well have worked; what failed is the
            // node's own import, which usually means its execution layer is
            // unsynced or the parent is not what this client thought. An
            // operator seeing this repeatedly has a beacon node problem, not a
            // validator one.
            Published::BroadcastNotImported => {
                warn!(
                    %slot,
                    validator,
                    "Block was broadcast but the beacon node could not import it; \
                     check that node's execution layer"
                );
                crate::metrics::inc_blocks_broadcast_not_imported();
            }
        }
        Ok(published)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_node::block_contents::SignedBlockContents;
    use crate::beacon_node::mock::MockBeaconNode;
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::primitives::{BlsPubkey, Bytes32, H160, Root};
    use libssz::SszDecode as _;

    fn secret() -> [u8; 32] {
        hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("valid hex")
            .try_into()
            .expect("32 bytes")
    }

    fn context() -> Arc<SigningContext> {
        Arc::new(SigningContext {
            config: Config::mainnet(),
            genesis_validators_root: Root::ZERO,
        })
    }

    /// A store holding one key, and the pubkey it resolves to.
    fn store() -> (RwLock<ValidatorStore>, BlsPubkey) {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        (RwLock::new(store), pubkey)
    }

    fn duty(pubkey: &BlsPubkey, validator_index: u64, slot: Slot) -> ProposerDutyDto {
        ProposerDutyDto {
            pubkey: crate::beacon_node::dto::encode_hex(&pubkey.0),
            validator_index,
            slot,
        }
    }

    fn service(node: Arc<MockBeaconNode>) -> ProposalService<MockBeaconNode> {
        let settings = ProposerSettings::new(Bytes32::repeat_byte(0xab), None);
        ProposalService::new(node, context(), Arc::new(settings))
    }

    fn service_expecting(
        node: Arc<MockBeaconNode>,
        fee_recipient: ExecutionAddress,
    ) -> ProposalService<MockBeaconNode> {
        let settings = ProposerSettings::new(Bytes32::repeat_byte(0xab), Some(fee_recipient));
        ProposalService::new(node, context(), Arc::new(settings))
    }

    /// A slot inside mainnet's electra era.
    ///
    /// Not an arbitrary small number: the mock produces an electra-shaped
    /// block and names electra, and `propose` refuses to sign when the node's
    /// fork and this client's schedule disagree. Slot 96 is phase0 on mainnet,
    /// so it would be refused, which is the behaviour these tests want
    /// everywhere except the one that asserts it.
    fn slot() -> Slot {
        use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
        Config::mainnet().electra_fork_epoch * SLOTS_PER_EPOCH + 96
    }

    #[tokio::test]
    async fn a_block_is_produced_signed_and_published() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));
        let service = service(node.clone());

        let published = service
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("proposes");
        assert_eq!(published, Published::Imported);

        let sent = node.published_blocks();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, ForkName::Electra);
    }

    /// The property the whole path exists to get right: the signature must
    /// cover the block the node produced, and the block must reach the wire
    /// unchanged.
    #[tokio::test]
    async fn the_published_body_carries_the_produced_block_and_a_matching_signature() {
        use blst::min_pk::{PublicKey, Signature};

        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));
        let service = service(node.clone());

        service
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("proposes");

        let (_, body) = node.published_blocks().remove(0);
        let decoded = SignedBlockContents::from_ssz_bytes(&body).expect("decodes");
        assert_eq!(decoded.signed_block.message.slot, slot());
        assert_eq!(decoded.signed_block.message.proposer_index, 7);

        let root =
            context().block_signing_root(decoded.signed_block.message.hash_tree_root(), slot());
        let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
        let sig =
            Signature::from_bytes(&decoded.signed_block.signature.0).expect("valid signature");
        assert_eq!(
            sig.verify(
                true,
                root.as_slice(),
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
                &[],
                &pk,
                true
            ),
            blst::BLST_ERROR::BLST_SUCCESS,
            "the published signature must verify over the published block"
        );
    }

    #[tokio::test]
    async fn the_configured_graffiti_reaches_the_block_request() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));
        service(node.clone())
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("proposes");

        // The mock builds its own block rather than echoing the request, so
        // the graffiti is asserted where it is actually carried: on the
        // request the node received.
        let seen = node.block_requests();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].graffiti, Bytes32::repeat_byte(0xab));
    }

    /// A per-validator graffiti replaces the default for that validator's
    /// block, and is read at proposal time, so one set after the service was
    /// built still applies.
    #[tokio::test]
    async fn a_validators_own_graffiti_replaces_the_default() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));
        let settings = Arc::new(ProposerSettings::new(Bytes32::repeat_byte(0xab), None));
        let service = ProposalService::new(node.clone(), context(), settings.clone());

        settings.set_graffiti(&pubkey, Bytes32::repeat_byte(0xcd));
        service
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("proposes");

        assert_eq!(
            node.block_requests()[0].graffiti,
            Bytes32::repeat_byte(0xcd)
        );
    }

    /// The reveal is over the slot's epoch, and it is what the node is given
    /// to build a body around. A client that signed the wrong epoch would get
    /// a block back and only find out when the network rejected it.
    #[tokio::test]
    async fn the_randao_reveal_is_signed_over_the_slots_epoch() {
        use blst::min_pk::{PublicKey, Signature};

        let (store, pubkey) = store();
        let slot = slot();
        let node = Arc::new(MockBeaconNode::new().with_block(slot, 7));
        service(node.clone())
            .propose(slot, &duty(&pubkey, 7, slot), &store)
            .await
            .expect("proposes");

        let reveal = node.block_requests().remove(0).randao_reveal;
        let root = context().randao_signing_root(compute_epoch_at_slot(slot));
        let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
        let sig = Signature::from_bytes(&reveal.0).expect("valid signature");
        assert_eq!(
            sig.verify(
                true,
                root.as_slice(),
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
                &[],
                &pk,
                true
            ),
            blst::BLST_ERROR::BLST_SUCCESS
        );
    }

    /// The guard is consulted before the block is asked for, not after, so a
    /// slot already proposed costs the beacon node nothing.
    #[tokio::test]
    async fn a_repeated_slot_is_refused_without_asking_for_a_block() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));
        let service = service(node.clone());

        service
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("first");
        let err = service
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect_err("a second block for one slot must be refused");

        assert!(matches!(err, Error::ProposalRefused { .. }), "got {err:?}");
        assert_eq!(
            node.block_requests().len(),
            1,
            "the refused attempt must not have asked the node for a block"
        );
        assert_eq!(node.published_blocks().len(), 1);
    }

    #[tokio::test]
    async fn a_node_that_cannot_import_the_block_is_reported_rather_than_hidden() {
        let (store, pubkey) = store();
        let node = Arc::new(
            MockBeaconNode::new()
                .with_block(slot(), 7)
                .with_publish_outcome(Published::BroadcastNotImported),
        );

        let published = service(node)
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("202 is not an error");
        assert_eq!(published, Published::BroadcastNotImported);
    }

    /// A duty naming a key this client does not hold must fail before anything
    /// is asked of the beacon node.
    #[tokio::test]
    async fn a_duty_for_an_unknown_validator_is_an_error() {
        let store = RwLock::new(ValidatorStore::new());
        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));

        let err = service(node.clone())
            .propose(slot(), &duty(&BlsPubkey([9; 48]), 7, slot()), &store)
            .await
            .expect_err("must fail");
        assert!(matches!(err, Error::UnknownValidator(_)), "got {err:?}");
        assert!(node.block_requests().is_empty());
    }

    /// The mock's block carries a zeroed fee recipient, so an expectation of
    /// anything else is a mismatch. The block must still be signed and
    /// published: refusing would forfeit the consensus reward as well as the
    /// execution one and cost the network a slot, while the execution reward
    /// was already going elsewhere the moment the node built the payload.
    #[tokio::test]
    async fn a_block_paying_the_wrong_address_is_still_published() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));

        let published = service_expecting(node.clone(), H160([0xfe; 20]))
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("a wrong fee recipient must not stop the proposal");

        assert_eq!(published, Published::Imported);
        assert_eq!(node.published_blocks().len(), 1);
    }

    #[tokio::test]
    async fn a_block_paying_the_expected_address_is_published_too() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_block(slot(), 7));

        // The fixture block's payload is zeroed, so the zero address is the
        // one it actually pays.
        service_expecting(node.clone(), H160([0; 20]))
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("proposes");
        assert_eq!(node.published_blocks().len(), 1);
    }

    /// The two forks in play must agree before anything is signed.
    ///
    /// The block is decoded and published under the fork the node named; the
    /// signing domain comes from this client's own schedule. A disagreement
    /// means one of them is wrong about where a fork boundary sits, and signing
    /// anyway yields a block rejected for a reason nothing in the logs would
    /// explain.
    ///
    /// The fixture makes them disagree the only way a test can: the mock always
    /// names electra, and slot 96 is phase0 on mainnet's schedule.
    #[tokio::test]
    async fn a_fork_the_client_does_not_expect_is_refused_before_signing() {
        let (store, pubkey) = store();
        let node = Arc::new(MockBeaconNode::new().with_block(96, 7));

        let err = service(node.clone())
            .propose(96, &duty(&pubkey, 7, 96), &store)
            .await
            .expect_err("a fork mismatch must not be signed");

        assert!(matches!(err, Error::InconsistentResponse(_)), "got {err:?}");
        assert!(
            node.published_blocks().is_empty(),
            "nothing may be published when the forks disagree"
        );
    }

    /// A failed production must leave the guard untouched, so the slot can
    /// still be proposed if a later attempt succeeds. Recording on the early
    /// check rather than at signing time would have burned it.
    ///
    /// The same service and the same node throughout, deliberately: a second
    /// service would carry a second, empty guard and the test would pass
    /// whether or not the first one recorded.
    #[tokio::test]
    async fn a_failed_production_does_not_burn_the_slot() {
        let (store, pubkey) = store();
        let node = Arc::new(
            MockBeaconNode::new()
                .with_block(slot(), 7)
                .failing_call("produce_block", "node is unhappy"),
        );
        let service = service(node.clone());

        service
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect_err("production failed");

        node.stop_failing("produce_block");
        service
            .propose(slot(), &duty(&pubkey, 7, slot()), &store)
            .await
            .expect("the slot was never recorded, so it can still be proposed");
        assert_eq!(node.published_blocks().len(), 1);
    }
}
