//! Producing the signatures a validator owes: attestations, the RANDAO reveal
//! a block carries, the block itself, and the two an aggregator needs.
//!
//! The signing root always comes from the SSZ container, never from the JSON a
//! beacon node sent: the wire representation is a transport detail, and the
//! chain only ever agrees about the merkle root.

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::constants::{
    DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_BUILDER,
    DOMAIN_BEACON_PROPOSER, DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_PTC_ATTESTER, DOMAIN_RANDAO,
    DOMAIN_SELECTION_PROOF, DOMAIN_SYNC_COMMITTEE, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
};
use ethlambda_types::beacon::containers::altair::{
    ContributionAndProof, SyncAggregatorSelectionData,
};
use ethlambda_types::beacon::containers::gloas::{
    ExecutionPayloadEnvelope, PayloadAttestationData,
};
use ethlambda_types::beacon::containers::shared::{AttestationData, BeaconBlockHeader, Fork};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{
    BLS_SIGNATURE_SIZE, BlsPubkey, BlsSignature, Domain, DomainType, Epoch, HashTreeRoot as _,
    Root, Slot,
};
// `AttestationData`, `Checkpoint`, `Fork` and `SigningData` all live in
// `containers::shared`, verified against `containers/shared.rs:158,120,97,220`.
use ethlambda_types::beacon::signing::{
    compute_domain, compute_epoch_at_slot, compute_signing_root,
};

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
use tokio::sync::RwLock;

use crate::error::{Error, Result};
use crate::keys::web3signer::{
    AggregationSlot, ForkInfo, RandaoReveal, SigningBody, SigningRequest, SyncCommitteeMessage,
    Versioned, VersionedHeader,
};
use crate::keys::{SigningMethod, ValidatorStore};

pub use crate::keys::web3signer::AggregateAndProofRef;

/// The ciphersuite the consensus layer pins BLS signatures to. It must match
/// `ethlambda_state_transition::beacon::bls`'s own constant, or nothing this
/// client signs will ever verify.
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// The chain-wide half of a signing domain, fixed for the life of the process.
///
/// The fork version deliberately does not live here. It is a function of the
/// epoch being signed for, and for an attestation that is the **target** epoch,
/// not the current one. Caching it would make every signature near a fork
/// boundary silently invalid.
pub struct SigningContext {
    /// The fork schedule signatures are resolved against.
    pub config: Config,
    /// The chain's genesis validators root, mixed into every domain so a
    /// signature from one chain never verifies on another running the same
    /// fork schedule.
    pub genesis_validators_root: Root,
    /// Selection proofs already produced; see [`Self::sign_selection_proof`].
    selection_proofs: Mutex<HashMap<(BlsPubkey, Slot), BlsSignature>>,
}

/// How long a selection proof is remembered past its slot: the duty
/// schedule holds the current epoch and the next, so a proof computed for a
/// subscription at the start of an epoch is still wanted by the aggregation
/// up to two epochs later.
const SELECTION_PROOF_RETENTION_SLOTS: Slot = 3 * SLOTS_PER_EPOCH;

/// How long one duty's batch of signatures may take, from when it is asked
/// for.
///
/// Well inside every duty's own budget (the rest of its slot, at least a
/// third of one), so a signer that hangs costs the signatures it owes and
/// nothing else: the batch is published with whatever arrived in time, local
/// keys and other signers' keys included. A healthy Web3Signer answers in
/// milliseconds; one slower than this is one whose signatures would land too
/// late to be worth much anyway.
pub const SIGNING_BUDGET: Duration = Duration::from_secs(2);

/// Ask for every signature in `requests` at once, and give each until
/// [`SIGNING_BUDGET`] from now.
///
/// One result per request, in order. A request still outstanding at the
/// deadline is dropped and reported as an [`Error::Signing`] for its key, so
/// one unresponsive signer delays the batch by the budget at most and never
/// takes the signatures that did arrive down with it.
pub async fn sign_all<T, F>(requests: impl IntoIterator<Item = (BlsPubkey, F)>) -> Vec<Result<T>>
where
    F: Future<Output = Result<T>>,
{
    let deadline = tokio::time::Instant::now() + SIGNING_BUDGET;
    futures::future::join_all(requests.into_iter().map(|(pubkey, request)| async move {
        tokio::time::timeout_at(deadline, request)
            .await
            .unwrap_or_else(|_| {
                Err(Error::Signing {
                    pubkey,
                    reason: format!(
                        "no signature within the {}s signing budget",
                        SIGNING_BUDGET.as_secs()
                    ),
                })
            })
    }))
    .await
}

impl SigningContext {
    pub fn new(config: Config, genesis_validators_root: Root) -> Self {
        Self {
            config,
            genesis_validators_root,
            selection_proofs: Mutex::new(HashMap::new()),
        }
    }

    /// The domain for `domain_type` as of `epoch`.
    pub fn domain(&self, domain_type: DomainType, epoch: Epoch) -> Domain {
        let fork = self.config.fork_at_epoch(epoch);
        compute_domain(
            domain_type,
            self.config.fork_version(fork),
            self.genesis_validators_root,
        )
    }

    /// The root an attestation's signature is computed over.
    pub fn attestation_signing_root(&self, data: &AttestationData) -> Root {
        let domain = self.domain(DOMAIN_BEACON_ATTESTER, data.target.epoch);
        compute_signing_root(data.hash_tree_root(), domain)
    }

    /// The root a block's RANDAO reveal is computed over.
    ///
    /// The message is the epoch itself, not anything about the block. That is
    /// what makes the reveal unforgeable *and* unchooseable: the proposer has
    /// exactly one valid signature to offer for its slot's epoch, so it cannot
    /// grind the randomness by trying alternatives.
    ///
    /// The `hash_tree_root` of a `uint64` is its eight little-endian bytes
    /// zero-padded to thirty-two, which is why this is not simply the epoch's
    /// bytes: it is a merkle root that happens to look like one.
    pub fn randao_signing_root(&self, epoch: Epoch) -> Root {
        let domain = self.domain(DOMAIN_RANDAO, epoch);
        compute_signing_root(epoch.hash_tree_root(), domain)
    }

    /// The root a block's own signature is computed over.
    ///
    /// Takes the block's already-computed `hash_tree_root` rather than the
    /// block, so that this stays independent of which fork's block shape the
    /// beacon node produced. The caller decodes the block, this signs its
    /// root.
    ///
    /// `slot` must be the block's own slot: unlike an attestation, whose
    /// domain comes from its *target* epoch, a block's comes from the epoch
    /// containing the slot it is proposed for.
    pub fn block_signing_root(&self, block_root: Root, slot: Slot) -> Root {
        let domain = self.domain(DOMAIN_BEACON_PROPOSER, compute_epoch_at_slot(slot));
        compute_signing_root(block_root, domain)
    }

    /// The root an aggregator's selection proof is computed over.
    ///
    /// The message is the slot, the same shape the RANDAO reveal uses for an
    /// epoch, and for a related reason: the signature has to be a function of
    /// the slot alone so that a validator gets exactly one answer per slot and
    /// cannot search for one that makes it an aggregator. See
    /// [`crate::aggregation_selection`].
    ///
    /// A different domain from the reveal, which is what stops one being
    /// replayed as the other. Both sign a bare `uint64` merkle root, so without
    /// the domain a reveal for epoch N would be a valid selection proof for
    /// slot N.
    pub fn selection_proof_signing_root(&self, slot: Slot) -> Root {
        let domain = self.domain(DOMAIN_SELECTION_PROOF, compute_epoch_at_slot(slot));
        compute_signing_root(slot.hash_tree_root(), domain)
    }

    /// The root a signed aggregate is computed over.
    ///
    /// Takes the `AggregateAndProof`'s already-computed root rather than the
    /// container, for the reason [`Self::block_signing_root`] does: this stays
    /// independent of which fork's attestation shape the aggregate carries,
    /// and electra widened that shape.
    ///
    /// Note what is signed. Not the aggregate attestation, whose signature is
    /// the attesters' own and was produced by somebody else; this covers the
    /// whole `AggregateAndProof`, binding the aggregator's index and its
    /// selection proof to the aggregate it is publishing.
    pub fn aggregate_and_proof_signing_root(&self, root: Root, slot: Slot) -> Root {
        let domain = self.domain(DOMAIN_AGGREGATE_AND_PROOF, compute_epoch_at_slot(slot));
        compute_signing_root(root, domain)
    }

    /// The root an execution payload envelope's signature is computed over.
    ///
    /// `slot` is the slot of the block the envelope reveals the payload for,
    /// not anything read out of the envelope: the domain is the builder's, at
    /// the epoch containing that slot (`get_domain(state, DOMAIN_BEACON_BUILDER,
    /// compute_epoch_at_slot(state.slot))` in the specification's
    /// `process_execution_payload`, where the state is the block's own).
    pub fn envelope_signing_root(&self, envelope: &ExecutionPayloadEnvelope, slot: Slot) -> Root {
        let domain = self.domain(DOMAIN_BEACON_BUILDER, compute_epoch_at_slot(slot));
        compute_signing_root(envelope.hash_tree_root(), domain)
    }

    /// The root a payload timeliness committee member's vote is computed over.
    ///
    /// The domain is taken at the epoch of `data.slot`, and the message is the
    /// data alone: the validator index travels beside the signature in the
    /// message wrapper and is deliberately not signed over.
    pub fn payload_attestation_signing_root(&self, data: &PayloadAttestationData) -> Root {
        let domain = self.domain(DOMAIN_PTC_ATTESTER, compute_epoch_at_slot(data.slot));
        compute_signing_root(data.hash_tree_root(), domain)
    }

    /// The root a sync committee message is computed over: the block root
    /// itself, under the sync committee domain at the epoch of `slot`.
    ///
    /// `slot` is the message's own slot. The domain comes from the fork
    /// schedule at that epoch rather than from any state's `fork`, which is
    /// what a node validating the message does too, so a head lagging across a
    /// fork boundary cannot make an honest message invalid.
    pub fn sync_committee_message_signing_root(&self, slot: Slot, beacon_block_root: Root) -> Root {
        let domain = self.domain(DOMAIN_SYNC_COMMITTEE, compute_epoch_at_slot(slot));
        compute_signing_root(beacon_block_root, domain)
    }

    /// The root a sync committee aggregator's selection proof is computed
    /// over: the slot and the subcommittee, under the selection domain.
    ///
    /// Both are in the message, unlike an attestation aggregator's proof which
    /// signs the slot alone, because every subcommittee holds its own draw.
    pub fn sync_selection_proof_signing_root(&self, slot: Slot, subcommittee_index: u64) -> Root {
        let data = SyncAggregatorSelectionData {
            slot,
            subcommittee_index,
        };
        let domain = self.domain(
            DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
            compute_epoch_at_slot(slot),
        );
        compute_signing_root(data.hash_tree_root(), domain)
    }

    /// The root a signed contribution is computed over: the whole
    /// `ContributionAndProof`, at the epoch of the contribution's slot.
    pub fn contribution_and_proof_signing_root(&self, message: &ContributionAndProof) -> Root {
        let domain = self.domain(
            DOMAIN_CONTRIBUTION_AND_PROOF,
            compute_epoch_at_slot(message.contribution.slot),
        );
        compute_signing_root(message.hash_tree_root(), domain)
    }

    /// The fork a message domained at `epoch` is signed under, told the way a
    /// remote signer wants it: the fork active at that epoch as `current`,
    /// the one before it as `previous`, and the epoch the current one took
    /// effect. Phase0 has no predecessor and names itself twice, as the
    /// genesis state's own `Fork` does.
    pub fn fork_info(&self, epoch: Epoch) -> ForkInfo {
        let fork = self.config.fork_at_epoch(epoch);
        let current_version = self.config.fork_version(fork);
        let previous_version = fork
            .previous()
            .map(|previous| self.config.fork_version(previous))
            .unwrap_or(current_version);
        ForkInfo {
            fork: Fork {
                previous_version,
                current_version,
                epoch: self.config.fork_epoch(fork),
            },
            genesis_validators_root: self.genesis_validators_root,
        }
    }

    /// Web3Signer's name for the fork at `epoch`: the specification's
    /// lowercase name in capitals (`ELECTRA`, `GLOAS`).
    fn fork_label(&self, epoch: Epoch) -> String {
        self.config.fork_at_epoch(epoch).as_str().to_uppercase()
    }

    /// Sign an already-computed signing root on behalf of `pubkey`.
    ///
    /// Every public signing method funnels through here, so there is one place
    /// a signature is actually produced. Deliberately private: a caller that
    /// can hand in an arbitrary root can make this client sign anything at
    /// all, and the domain separation that keeps an attestation from being
    /// read as a block lives in the callers above.
    ///
    /// `epoch` is the epoch the root's domain was taken at, and `body` the
    /// message itself; a local key needs neither, a remote signer needs both.
    ///
    /// The store's read guard is held for the lookup alone and released before
    /// anything is signed. `tokio::sync::RwLock` is write-preferring, so a
    /// guard held across the remote signer's round trip would let one queued
    /// keymanager writer stall every other duty behind it for that long.
    async fn sign(
        &self,
        store: &RwLock<ValidatorStore>,
        pubkey: &BlsPubkey,
        root: Root,
        epoch: Epoch,
        body: SigningBody<'_>,
    ) -> Result<BlsSignature> {
        let method = store
            .read()
            .await
            .signer(pubkey)
            .ok_or(Error::UnknownValidator(*pubkey))?;
        match method {
            SigningMethod::LocalKeystore { secret_key } => {
                let signature = secret_key.sign(root.as_slice(), DST, &[]);
                let bytes: [u8; BLS_SIGNATURE_SIZE] = signature.to_bytes();
                Ok(BlsSignature(bytes))
            }
            SigningMethod::Web3Signer { signer } => {
                // Web3Signer's `BLOCK_V2` takes the full block before
                // bellatrix and the header only from bellatrix on, and this
                // client only ever sends the header. Refused here rather than
                // sent in a shape the signer answers with a 400; the proposal
                // path refuses those forks long before this anyway.
                if matches!(body, SigningBody::Block { .. })
                    && self.config.fork_at_epoch(epoch) < ForkName::Bellatrix
                {
                    return Err(Error::Signing {
                        pubkey: *pubkey,
                        reason: "a remote signer is only asked for blocks from bellatrix on"
                            .to_string(),
                    });
                }
                let request = SigningRequest::new(self.fork_info(epoch), root, body);
                signer.sign(pubkey, &request).await
            }
        }
    }

    /// Sign `data` on behalf of `pubkey`.
    pub async fn sign_attestation(
        &self,
        store: &RwLock<ValidatorStore>,
        pubkey: &BlsPubkey,
        data: &AttestationData,
    ) -> Result<BlsSignature> {
        self.sign(
            store,
            pubkey,
            self.attestation_signing_root(data),
            data.target.epoch,
            SigningBody::Attestation { attestation: data },
        )
        .await
    }

    /// Sign the RANDAO reveal for `epoch` on behalf of `pubkey`.
    ///
    /// Unlike the other two, this signature is not itself a slashable message:
    /// it commits to an epoch, not to a chain position, and producing one for
    /// an epoch a validator is not proposing in reveals nothing and risks
    /// nothing. It is therefore not guarded, and does not need to be.
    pub async fn sign_randao(
        &self,
        store: &RwLock<ValidatorStore>,
        pubkey: &BlsPubkey,
        epoch: Epoch,
    ) -> Result<BlsSignature> {
        self.sign(
            store,
            pubkey,
            self.randao_signing_root(epoch),
            epoch,
            SigningBody::RandaoReveal {
                randao_reveal: RandaoReveal { epoch },
            },
        )
        .await
    }

    /// Sign the selection proof for `slot` on behalf of `pubkey`.
    ///
    /// Not slashable, and not guarded. A selection proof commits to a slot, not
    /// to a chain position, so producing one twice is producing the same bytes
    /// twice: BLS signatures are deterministic, which is the property the
    /// selection rule rests on.
    ///
    /// That determinism is also why the answer is remembered. The same proof
    /// is wanted once when the epoch's subscriptions are sent and again by the
    /// aggregation tick, and for a remote key each ask is a round trip; a
    /// remembered proof is the very signature the signer would return. Only
    /// a proof that was produced is remembered, so a failure is asked again.
    pub async fn sign_selection_proof(
        &self,
        store: &RwLock<ValidatorStore>,
        pubkey: &BlsPubkey,
        slot: Slot,
    ) -> Result<BlsSignature> {
        if let Some(proof) = self.selection_proofs().get(&(*pubkey, slot)) {
            return Ok(*proof);
        }
        let proof = self
            .sign(
                store,
                pubkey,
                self.selection_proof_signing_root(slot),
                compute_epoch_at_slot(slot),
                SigningBody::AggregationSlot {
                    aggregation_slot: AggregationSlot { slot },
                },
            )
            .await?;
        let mut proofs = self.selection_proofs();
        proofs.retain(|(_, held), _| held + SELECTION_PROOF_RETENTION_SLOTS >= slot);
        proofs.insert((*pubkey, slot), proof);
        Ok(proof)
    }

    /// The remembered selection proofs. A poisoned map is still a map of
    /// valid proofs, since an entry is inserted whole or not at all.
    fn selection_proofs(&self) -> MutexGuard<'_, HashMap<(BlsPubkey, Slot), BlsSignature>> {
        self.selection_proofs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Sign `message`, an aggregator's `AggregateAndProof`, on behalf of
    /// `pubkey`.
    ///
    /// Not slashable either, which is worth stating because it is the only
    /// signature here that covers an attestation and is not. The slashing
    /// conditions are about a validator's *own* vote; an aggregator is
    /// republishing other validators' votes with a wrapper saying who
    /// collected them, and publishing two different aggregates for one slot is
    /// wasteful rather than punishable.
    ///
    /// Takes the whole wrapper rather than its root: a remote signer wants to
    /// read what it signs, and the wrapper's own fork decides its JSON shape.
    pub async fn sign_aggregate_and_proof(
        &self,
        store: &RwLock<ValidatorStore>,
        pubkey: &BlsPubkey,
        message: AggregateAndProofRef<'_>,
    ) -> Result<BlsSignature> {
        let slot = message.slot();
        let epoch = compute_epoch_at_slot(slot);
        let version = match message {
            AggregateAndProofRef::Gloas(_) => ForkName::Gloas.as_str().to_uppercase(),
            AggregateAndProofRef::Electra(_) => self.fork_label(epoch),
        };
        self.sign(
            store,
            pubkey,
            self.aggregate_and_proof_signing_root(message.hash_tree_root(), slot),
            epoch,
            SigningBody::AggregateAndProof {
                aggregate_and_proof: Versioned {
                    version,
                    data: message,
                },
            },
        )
        .await
    }

    /// Sign the envelope revealing the payload of the block proposed for `slot`
    /// on behalf of `pubkey`, which for a self-built payload is the proposer's
    /// own key.
    ///
    /// Not slashable and not guarded. The specification attaches no slashing
    /// condition to an envelope: signing two for one slot is at worst a
    /// payload the network ignores one of. The block it belongs to is the
    /// guarded signature.
    pub async fn sign_execution_payload_envelope(
        &self,
        store: &RwLock<ValidatorStore>,
        pubkey: &BlsPubkey,
        envelope: &ExecutionPayloadEnvelope,
        slot: Slot,
    ) -> Result<BlsSignature> {
        self.sign(
            store,
            pubkey,
            self.envelope_signing_root(envelope, slot),
            compute_epoch_at_slot(slot),
            SigningBody::ExecutionPayloadEnvelope {
                execution_payload_envelope: Versioned {
                    version: ForkName::Gloas.as_str().to_uppercase(),
                    data: envelope,
                },
            },
        )
        .await
    }

    /// Sign a payload timeliness committee vote on behalf of `pubkey`.
    ///
    /// Not slashable by the specification, and deduplicated per validator and
    /// slot by [`crate::payload_attestation`] only to avoid publishing the same
    /// vote twice.
    pub async fn sign_payload_attestation(
        &self,
        store: &RwLock<ValidatorStore>,
        pubkey: &BlsPubkey,
        data: &PayloadAttestationData,
    ) -> Result<BlsSignature> {
        self.sign(
            store,
            pubkey,
            self.payload_attestation_signing_root(data),
            compute_epoch_at_slot(data.slot),
            SigningBody::PayloadAttestationMessage {
                payload_attestation_message: Versioned {
                    version: ForkName::Gloas.as_str().to_uppercase(),
                    data,
                },
            },
        )
        .await
    }

    /// Sign a sync committee message for `slot` over `beacon_block_root`.
    ///
    /// Not slashable, and deduplicated per validator and slot by
    /// [`crate::sync_committee`] only to avoid publishing the same message
    /// twice.
    pub async fn sign_sync_committee_message(
        &self,
        store: &RwLock<ValidatorStore>,
        pubkey: &BlsPubkey,
        slot: Slot,
        beacon_block_root: Root,
    ) -> Result<BlsSignature> {
        self.sign(
            store,
            pubkey,
            self.sync_committee_message_signing_root(slot, beacon_block_root),
            compute_epoch_at_slot(slot),
            SigningBody::SyncCommitteeMessage {
                sync_committee_message: SyncCommitteeMessage {
                    beacon_block_root,
                    slot,
                },
            },
        )
        .await
    }

    /// Sign the sync committee selection proof for `slot` and one
    /// subcommittee. Deterministic, so not guarded, for the reason
    /// [`Self::sign_selection_proof`] is not.
    pub async fn sign_sync_selection_proof(
        &self,
        store: &RwLock<ValidatorStore>,
        pubkey: &BlsPubkey,
        slot: Slot,
        subcommittee_index: u64,
    ) -> Result<BlsSignature> {
        self.sign(
            store,
            pubkey,
            self.sync_selection_proof_signing_root(slot, subcommittee_index),
            compute_epoch_at_slot(slot),
            SigningBody::SyncCommitteeSelectionProof {
                sync_aggregator_selection_data: SyncAggregatorSelectionData {
                    slot,
                    subcommittee_index,
                },
            },
        )
        .await
    }

    /// Sign a `ContributionAndProof` on behalf of its aggregator `pubkey`.
    pub async fn sign_contribution_and_proof(
        &self,
        store: &RwLock<ValidatorStore>,
        pubkey: &BlsPubkey,
        message: &ContributionAndProof,
    ) -> Result<BlsSignature> {
        self.sign(
            store,
            pubkey,
            self.contribution_and_proof_signing_root(message),
            compute_epoch_at_slot(message.contribution.slot),
            SigningBody::SyncCommitteeContributionAndProof {
                contribution_and_proof: message,
            },
        )
        .await
    }

    /// Sign the block whose header is `header` on behalf of `pubkey`.
    ///
    /// The root signed is the header's, which is the block's: a header is the
    /// block with its body replaced by that body's root, and the two
    /// merkleize to the same value. The header rather than the root travels
    /// because a remote signer reads it to keep its slashing-protection
    /// record.
    ///
    /// This one *is* slashable, and is the most expensive signature this
    /// client can get wrong: two distinct blocks for one slot need no second
    /// validator to be caught, since the two signed headers are the whole
    /// evidence. Callers must pass it through
    /// [`crate::proposal_guard::ProposalGuard`] first.
    pub async fn sign_block(
        &self,
        store: &RwLock<ValidatorStore>,
        pubkey: &BlsPubkey,
        header: &BeaconBlockHeader,
    ) -> Result<BlsSignature> {
        let epoch = compute_epoch_at_slot(header.slot);
        self.sign(
            store,
            pubkey,
            self.block_signing_root(header.hash_tree_root(), header.slot),
            epoch,
            SigningBody::Block {
                beacon_block: VersionedHeader {
                    version: self.fork_label(epoch),
                    block_header: header.clone(),
                },
            },
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::containers::shared::Checkpoint;
    use ethlambda_types::beacon::preset;

    fn secret() -> [u8; 32] {
        hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("valid hex")
            .try_into()
            .expect("32 bytes")
    }

    fn context() -> SigningContext {
        SigningContext::new(Config::mainnet(), Root::ZERO)
    }

    fn attestation_data(target_epoch: Epoch) -> AttestationData {
        AttestationData {
            slot: target_epoch * 32,
            index: 0,
            beacon_block_root: Root::ZERO,
            source: Checkpoint {
                epoch: target_epoch.saturating_sub(1),
                root: Root::ZERO,
            },
            target: Checkpoint {
                epoch: target_epoch,
                root: Root::ZERO,
            },
        }
    }

    #[tokio::test]
    async fn a_signature_verifies_under_the_signing_root() {
        use blst::min_pk::{PublicKey, Signature};

        let (store, pubkey) = store_with_key();
        let context = context();
        let data = attestation_data(100);

        let signature = context
            .sign_attestation(&store, &pubkey, &data)
            .await
            .expect("signs");

        let root = context.attestation_signing_root(&data);
        let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
        let sig = Signature::from_bytes(&signature.0).expect("valid signature");
        assert_eq!(
            sig.verify(true, root.as_slice(), DST, &[], &pk, true),
            blst::BLST_ERROR::BLST_SUCCESS
        );
    }

    /// One request that never answers costs its own signature, after the
    /// budget, and nothing else: the others come back as they were.
    #[tokio::test(start_paused = true)]
    async fn a_signature_past_the_budget_does_not_hold_back_the_rest() {
        use futures::FutureExt as _;

        let started = tokio::time::Instant::now();
        let answered = BlsPubkey([1; 48]);
        let hung = BlsPubkey([2; 48]);
        let results = sign_all([
            (answered, async { Ok(7u8) }.boxed()),
            (hung, std::future::pending().boxed()),
        ])
        .await;

        assert_eq!(started.elapsed(), SIGNING_BUDGET);
        assert!(matches!(results[0], Ok(7)));
        assert!(
            matches!(&results[1], Err(Error::Signing { pubkey, .. }) if *pubkey == hung),
            "the late one is a signing failure for its own key"
        );
    }

    #[tokio::test]
    async fn a_selection_proof_is_remembered_once_produced() {
        let (store, pubkey) = store_with_key();
        let context = context();
        let first = context
            .sign_selection_proof(&store, &pubkey, 3200)
            .await
            .expect("signs");

        // With the key gone, only the remembered proof can answer.
        assert!(store.write().await.remove(&pubkey));
        let again = context
            .sign_selection_proof(&store, &pubkey, 3200)
            .await
            .expect("remembered");
        assert_eq!(first, again);
        assert!(
            context
                .sign_selection_proof(&store, &pubkey, 3201)
                .await
                .is_err(),
            "another slot is another proof"
        );
    }

    #[test]
    fn the_domain_changes_with_the_epoch() {
        let context = context();
        let early = context.domain(DOMAIN_BEACON_ATTESTER, 0);
        let late = context.domain(DOMAIN_BEACON_ATTESTER, 1_000_000);
        assert_ne!(
            early, late,
            "epochs on either side of a fork must give different domains"
        );
    }

    /// The domain must come from the attestation's target epoch, never from
    /// its slot. Real attestations have the two agree, which is exactly why a
    /// regression swapping them would go unnoticed: this fixture pulls them
    /// apart on purpose so the assertion has something to catch.
    #[test]
    fn the_signing_root_uses_the_target_epoch_not_the_slot_epoch() {
        let context = context();

        // Target lands after altair activates; the slot lands in phase0. The
        // gap has to cross an actual fork boundary, not just be a large
        // number, since `domain()` only changes with the epoch insofar as the
        // epoch selects a different fork version.
        let mut data = attestation_data(context.config.altair_fork_epoch + 1);
        data.slot = 3 * preset::SLOTS_PER_EPOCH;

        let from_target = compute_signing_root(
            data.hash_tree_root(),
            context.domain(DOMAIN_BEACON_ATTESTER, data.target.epoch),
        );
        let from_slot = compute_signing_root(
            data.hash_tree_root(),
            context.domain(DOMAIN_BEACON_ATTESTER, compute_epoch_at_slot(data.slot)),
        );
        assert_ne!(
            from_target, from_slot,
            "the fixture must actually distinguish the two, or this test proves nothing"
        );
        assert_eq!(context.attestation_signing_root(&data), from_target);
    }

    #[tokio::test]
    async fn signing_for_an_unknown_validator_is_an_error() {
        let store = RwLock::new(ValidatorStore::new());
        let err = context()
            .sign_attestation(&store, &BlsPubkey::default(), &attestation_data(1))
            .await
            .expect_err("must fail");
        assert!(matches!(err, Error::UnknownValidator(_)), "got {err:?}");
    }

    /// Verifies a signature produced by one of the three signing methods
    /// against the root that method says it signed. Shared so each method's
    /// test asserts the same property and cannot drift into asserting a
    /// weaker one.
    fn verify(pubkey: &BlsPubkey, signature: &BlsSignature, root: Root) -> bool {
        use blst::min_pk::{PublicKey, Signature};

        let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
        let sig = Signature::from_bytes(&signature.0).expect("valid signature");
        sig.verify(true, root.as_slice(), DST, &[], &pk, true) == blst::BLST_ERROR::BLST_SUCCESS
    }

    fn store_with_key() -> (RwLock<ValidatorStore>, BlsPubkey) {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        (RwLock::new(store), pubkey)
    }

    fn header(slot: Slot) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot,
            proposer_index: 7,
            parent_root: Root::repeat_byte(1),
            state_root: Root::repeat_byte(2),
            body_root: Root::repeat_byte(3),
        }
    }

    #[tokio::test]
    async fn a_randao_reveal_verifies_under_the_randao_signing_root() {
        let (store, pubkey) = store_with_key();
        let context = context();

        let signature = context
            .sign_randao(&store, &pubkey, 100)
            .await
            .expect("signs");
        assert!(verify(
            &pubkey,
            &signature,
            context.randao_signing_root(100)
        ));
    }

    #[tokio::test]
    async fn a_block_signature_verifies_under_the_block_signing_root() {
        let (store, pubkey) = store_with_key();
        let context = context();
        let header = header(3200);

        let signature = context
            .sign_block(&store, &pubkey, &header)
            .await
            .expect("signs");
        assert!(verify(
            &pubkey,
            &signature,
            context.block_signing_root(header.hash_tree_root(), 3200)
        ));
    }

    /// What the RANDAO reveal actually commits to: the epoch's merkle root,
    /// which for a `uint64` is its eight little-endian bytes zero-padded to
    /// thirty-two. A client that signed the epoch's big-endian bytes, or its
    /// raw eight bytes unpadded, would produce a reveal the network rejects
    /// and would have no way to tell why.
    #[test]
    fn the_randao_message_is_the_epochs_little_endian_merkle_root() {
        let epoch: Epoch = 0x0102_0304_0506_0708;
        let mut expected = [0u8; 32];
        expected[..8].copy_from_slice(&epoch.to_le_bytes());
        assert_eq!(epoch.hash_tree_root().0, expected);

        let context = context();
        assert_eq!(
            context.randao_signing_root(epoch),
            compute_signing_root(Root::from(expected), context.domain(DOMAIN_RANDAO, epoch))
        );
    }

    /// Domain separation, stated as the property that matters rather than as
    /// three constants being different. One 32-byte object root signed under
    /// the three domains this client uses must give three distinct signing
    /// roots, so a signature obtained for one purpose can never be replayed as
    /// another.
    ///
    /// This is not hypothetical for the RANDAO reveal specifically: its
    /// message is a bare `uint64` merkle root, which is also a perfectly
    /// well-formed block root. Without the domain in the mix, a reveal for
    /// epoch N would be a valid proposer signature for a block whose root
    /// happened to be N's merkle root.
    #[test]
    fn one_object_root_signs_differently_under_each_domain() {
        let context = context();
        let epoch: Epoch = 100;
        let object = epoch.hash_tree_root();
        let slot = epoch * preset::SLOTS_PER_EPOCH;

        let roots = [
            compute_signing_root(object, context.domain(DOMAIN_BEACON_ATTESTER, epoch)),
            context.randao_signing_root(epoch),
            context.block_signing_root(object, slot),
            context.selection_proof_signing_root(slot),
            context.aggregate_and_proof_signing_root(object, slot),
        ];

        for (first, left) in roots.iter().enumerate() {
            for right in &roots[first + 1..] {
                assert_ne!(
                    left, right,
                    "every domain must give a distinct signing root for one object"
                );
            }
        }
    }

    /// The sharpest case of the property above, stated on its own because the
    /// two messages are genuinely interchangeable without it. A RANDAO reveal
    /// signs an epoch's merkle root and a selection proof signs a slot's; both
    /// are bare `uint64` roots, so for epoch N and slot N the object is byte
    /// for byte the same, and only the domain tells them apart.
    #[test]
    fn a_randao_reveal_cannot_be_replayed_as_a_selection_proof() {
        let context = context();
        let n: u64 = 100;
        assert_eq!(
            Epoch::hash_tree_root(&n),
            Slot::hash_tree_root(&n),
            "the fixture must actually collide, or this test proves nothing"
        );
        assert_ne!(
            context.randao_signing_root(n),
            context.selection_proof_signing_root(n)
        );
    }

    /// A block's domain comes from the epoch containing its own slot. The
    /// fixture crosses a real fork boundary, because `domain()` only changes
    /// with the epoch insofar as the epoch selects a different fork version;
    /// two large epochs in the same fork would prove nothing.
    #[test]
    fn a_blocks_domain_comes_from_its_own_slots_epoch() {
        let context = context();
        let after = context.config.altair_fork_epoch * preset::SLOTS_PER_EPOCH;
        let before = after - 1;

        assert_ne!(
            context.block_signing_root(Root::ZERO, before),
            context.block_signing_root(Root::ZERO, after),
            "slots on either side of a fork boundary must sign under different domains"
        );
        assert_eq!(
            context.block_signing_root(Root::ZERO, after),
            compute_signing_root(
                Root::ZERO,
                context.domain(DOMAIN_BEACON_PROPOSER, compute_epoch_at_slot(after))
            )
        );
    }

    #[tokio::test]
    async fn signing_a_block_for_an_unknown_validator_is_an_error() {
        let store = RwLock::new(ValidatorStore::new());
        let err = context()
            .sign_block(&store, &BlsPubkey::default(), &header(1))
            .await
            .expect_err("must fail");
        assert!(matches!(err, Error::UnknownValidator(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_selection_proof_verifies_under_its_own_root() {
        let (store, pubkey) = store_with_key();
        let context = context();

        let signature = context
            .sign_selection_proof(&store, &pubkey, 3200)
            .await
            .expect("signs");
        assert!(verify(
            &pubkey,
            &signature,
            context.selection_proof_signing_root(3200)
        ));
    }

    #[tokio::test]
    async fn an_aggregate_signature_verifies_under_its_own_root() {
        use ethlambda_types::beacon::containers::electra;

        let (store, pubkey) = store_with_key();
        let context = context();
        let message = electra::AggregateAndProof {
            aggregator_index: 9,
            aggregate: electra::Attestation {
                aggregation_bits: Default::default(),
                data: attestation_data(100),
                signature: BlsSignature([2; 96]),
                committee_bits: Default::default(),
            },
            selection_proof: BlsSignature([3; 96]),
        };

        let signature = context
            .sign_aggregate_and_proof(&store, &pubkey, AggregateAndProofRef::Electra(&message))
            .await
            .expect("signs");
        assert!(verify(
            &pubkey,
            &signature,
            context.aggregate_and_proof_signing_root(message.hash_tree_root(), 3200)
        ));
    }

    #[tokio::test]
    async fn a_sync_committee_message_verifies_under_its_own_root() {
        let (store, pubkey) = store_with_key();
        let context = context();
        let root = Root::repeat_byte(5);

        let signature = context
            .sign_sync_committee_message(&store, &pubkey, 3200, root)
            .await
            .expect("signs");
        assert!(verify(
            &pubkey,
            &signature,
            context.sync_committee_message_signing_root(3200, root)
        ));
        assert_eq!(
            context.sync_committee_message_signing_root(3200, root),
            compute_signing_root(root, context.domain(DOMAIN_SYNC_COMMITTEE, 100)),
            "the root is signed bare, under the sync committee domain"
        );
    }

    /// The domain follows the message's slot across a fork boundary.
    #[test]
    fn a_sync_message_domain_follows_the_fork_schedule_at_its_slot() {
        let context = context();
        let after = context.config.altair_fork_epoch * preset::SLOTS_PER_EPOCH;
        assert_ne!(
            context.sync_committee_message_signing_root(after - 1, Root::ZERO),
            context.sync_committee_message_signing_root(after, Root::ZERO),
        );
    }

    #[tokio::test]
    async fn a_sync_selection_proof_verifies_and_names_the_subcommittee() {
        let (store, pubkey) = store_with_key();
        let context = context();

        let signature = context
            .sign_sync_selection_proof(&store, &pubkey, 3200, 2)
            .await
            .expect("signs");
        assert!(verify(
            &pubkey,
            &signature,
            context.sync_selection_proof_signing_root(3200, 2)
        ));
        assert_ne!(
            context.sync_selection_proof_signing_root(3200, 2),
            context.sync_selection_proof_signing_root(3200, 3),
            "each subcommittee has its own draw"
        );
        assert_ne!(
            context.sync_selection_proof_signing_root(3200, 0),
            context.selection_proof_signing_root(3200),
            "not replayable as an attestation selection proof"
        );
    }

    #[tokio::test]
    async fn a_contribution_and_proof_verifies_under_its_own_root() {
        use ethlambda_types::beacon::containers::altair::SyncCommitteeContribution;

        let (store, pubkey) = store_with_key();
        let context = context();
        let message = ContributionAndProof {
            aggregator_index: 9,
            contribution: SyncCommitteeContribution {
                slot: 3200,
                beacon_block_root: Root::repeat_byte(1),
                subcommittee_index: 1,
                aggregation_bits: Default::default(),
                signature: BlsSignature([2; 96]),
            },
            selection_proof: BlsSignature([3; 96]),
        };

        let signature = context
            .sign_contribution_and_proof(&store, &pubkey, &message)
            .await
            .expect("signs");
        assert!(verify(
            &pubkey,
            &signature,
            context.contribution_and_proof_signing_root(&message)
        ));
    }

    #[tokio::test]
    async fn signing_a_randao_reveal_for_an_unknown_validator_is_an_error() {
        let store = RwLock::new(ValidatorStore::new());
        let err = context()
            .sign_randao(&store, &BlsPubkey::default(), 1)
            .await
            .expect_err("must fail");
        assert!(matches!(err, Error::UnknownValidator(_)), "got {err:?}");
    }

    /// `fork_info` must describe the fork at the epoch the domain was taken
    /// at, since the remote signer recomputes the domain from it. Mainnet's
    /// altair boundary pins all three fields on either side.
    #[test]
    fn fork_info_names_the_fork_at_the_epoch_and_its_predecessor() {
        let context = context();
        let altair = context.config.altair_fork_epoch;

        let before = context.fork_info(altair - 1);
        assert_eq!(
            before.fork.current_version,
            context.config.genesis_fork_version
        );
        assert_eq!(
            before.fork.previous_version, before.fork.current_version,
            "phase0 has no predecessor and names itself twice"
        );
        assert_eq!(before.fork.epoch, 0);

        let after = context.fork_info(altair);
        assert_eq!(
            after.fork.current_version,
            context.config.altair_fork_version
        );
        assert_eq!(
            after.fork.previous_version,
            context.config.genesis_fork_version
        );
        assert_eq!(after.fork.epoch, altair);
        assert_eq!(
            after.genesis_validators_root,
            context.genesis_validators_root
        );
    }

    /// A remote signer, stood in for by a local HTTP server: the request it
    /// receives is the one Web3Signer documents, and the signature it returns
    /// is what the caller gets back.
    mod remote {
        use super::*;
        use axum::Router;
        use axum::extract::{Path, State};
        use axum::http::StatusCode;
        use axum::routing::post;
        use std::sync::{Arc, Mutex};

        /// What the fake signer does: records every request and answers with
        /// a fixed signature, or with a fixed status.
        #[derive(Clone)]
        struct Fake {
            requests: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
            answer: Arc<Mutex<Answer>>,
        }

        #[derive(Clone, Copy)]
        enum Answer {
            Signature,
            Status(u16),
        }

        async fn handle(
            State(fake): State<Fake>,
            Path(pubkey): Path<String>,
            body: String,
        ) -> (StatusCode, String) {
            let json: serde_json::Value = serde_json::from_str(&body).expect("json body");
            fake.requests.lock().expect("lock").push((pubkey, json));
            match *fake.answer.lock().expect("lock") {
                Answer::Signature => (
                    StatusCode::OK,
                    format!("{{\"signature\":\"0x{}\"}}", "ab".repeat(96)),
                ),
                Answer::Status(code) => (
                    StatusCode::from_u16(code).expect("status"),
                    "refused".to_string(),
                ),
            }
        }

        /// Start the fake on an ephemeral port and return it with its URL.
        async fn serve(answer: Answer) -> (Fake, String) {
            let fake = Fake {
                requests: Arc::new(Mutex::new(Vec::new())),
                answer: Arc::new(Mutex::new(answer)),
            };
            let app = Router::new()
                .route("/api/v1/eth2/sign/{pubkey}", post(handle))
                .with_state(fake.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("binds");
            let address = listener.local_addr().expect("address");
            tokio::spawn(async move {
                axum::serve(listener, app).await.expect("serves");
            });
            (fake, format!("http://{address}"))
        }

        fn remote_store(url: &str) -> (RwLock<ValidatorStore>, BlsPubkey) {
            let pubkey = BlsPubkey([0x42; 48]);
            let mut store = ValidatorStore::new();
            store.insert_remote(pubkey, url).expect("inserts");
            (RwLock::new(store), pubkey)
        }

        #[tokio::test]
        async fn an_attestation_is_signed_by_the_remote_signer() {
            let (fake, url) = serve(Answer::Signature).await;
            let (store, pubkey) = remote_store(&url);
            let context = context();
            let data = attestation_data(context.config.altair_fork_epoch + 1);

            let signature = context
                .sign_attestation(&store, &pubkey, &data)
                .await
                .expect("signs");
            assert_eq!(signature.0, [0xab; 96]);

            let requests = fake.requests.lock().expect("lock");
            assert_eq!(requests.len(), 1);
            let (path_pubkey, body) = &requests[0];
            assert_eq!(path_pubkey, &format!("0x{}", "42".repeat(48)));
            assert_eq!(body["type"], "ATTESTATION");
            assert_eq!(
                body["signingRoot"],
                serde_json::to_value(context.attestation_signing_root(&data)).expect("root")
            );
            assert_eq!(
                body["attestation"]["target"]["epoch"],
                data.target.epoch.to_string()
            );
            assert_eq!(
                body["fork_info"],
                serde_json::to_value(context.fork_info(data.target.epoch)).expect("fork info"),
                "the fork is the target epoch's, where the domain came from"
            );
        }

        #[tokio::test]
        async fn a_block_request_names_the_fork_and_carries_the_header() {
            let (fake, url) = serve(Answer::Signature).await;
            let (store, pubkey) = remote_store(&url);
            let context = context();
            let slot = context.config.electra_fork_epoch * preset::SLOTS_PER_EPOCH;
            let header = header(slot);

            context
                .sign_block(&store, &pubkey, &header)
                .await
                .expect("signs");

            let requests = fake.requests.lock().expect("lock");
            let body = &requests[0].1;
            assert_eq!(body["type"], "BLOCK_V2");
            assert_eq!(body["beacon_block"]["version"], "ELECTRA");
            assert_eq!(
                body["beacon_block"]["block_header"]["slot"],
                slot.to_string()
            );
            assert_eq!(
                body["signingRoot"],
                serde_json::to_value(context.block_signing_root(header.hash_tree_root(), slot))
                    .expect("root")
            );
        }

        /// Before bellatrix the signer wants the full block, which this
        /// client never sends, so the request is refused rather than made.
        #[tokio::test]
        async fn a_pre_bellatrix_block_is_not_sent_to_the_signer() {
            let (fake, url) = serve(Answer::Signature).await;
            let (store, pubkey) = remote_store(&url);
            let context = context();
            let slot = context.config.altair_fork_epoch * preset::SLOTS_PER_EPOCH;

            let err = context
                .sign_block(&store, &pubkey, &header(slot))
                .await
                .expect_err("refused");
            assert!(matches!(err, Error::Signing { .. }), "got {err:?}");
            assert!(fake.requests.lock().expect("lock").is_empty());
        }

        #[tokio::test]
        async fn a_slashing_protection_refusal_is_a_signing_error() {
            let (_fake, url) = serve(Answer::Status(412)).await;
            let (store, pubkey) = remote_store(&url);

            let err = context()
                .sign_attestation(&store, &pubkey, &attestation_data(100))
                .await
                .expect_err("must fail");
            assert!(matches!(err, Error::Signing { .. }), "got {err:?}");
            assert!(err.to_string().contains("slashing protection"), "{err}");
            assert!(!err.is_retryable());
        }

        #[tokio::test]
        async fn a_key_the_signer_does_not_hold_is_a_signing_error() {
            let (_fake, url) = serve(Answer::Status(404)).await;
            let (store, pubkey) = remote_store(&url);

            let err = context()
                .sign_randao(&store, &pubkey, 1)
                .await
                .expect_err("must fail");
            assert!(matches!(err, Error::Signing { .. }), "got {err:?}");
            assert!(err.to_string().contains("does not hold"), "{err}");
        }

        #[tokio::test]
        async fn an_unreachable_signer_is_a_signing_error() {
            // Nothing listens on port 9 (discard), and a connection refused
            // comes back at once rather than after the request timeout.
            let (store, pubkey) = remote_store("http://127.0.0.1:9");

            let err = context()
                .sign_randao(&store, &pubkey, 1)
                .await
                .expect_err("must fail");
            assert!(matches!(err, Error::Signing { .. }), "got {err:?}");
        }
    }
}
