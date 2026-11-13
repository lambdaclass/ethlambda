//! Producing the signatures a validator owes: attestations, the RANDAO reveal
//! a block carries, the block itself, the two an aggregator needs, and the one
//! an operator asks for when a validator leaves: the voluntary exit.
//!
//! The signing root always comes from the SSZ container, never from the JSON a
//! beacon node sent: the wire representation is a transport detail, and the
//! chain only ever agrees about the merkle root.

use ethlambda_types::beacon::builder::ValidatorRegistrationV1;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::constants::{
    DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_BUILDER,
    DOMAIN_BEACON_PROPOSER, DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_PROPOSER_PREFERENCES,
    DOMAIN_PTC_ATTESTER, DOMAIN_RANDAO, DOMAIN_SELECTION_PROOF, DOMAIN_SYNC_COMMITTEE,
    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, DOMAIN_VOLUNTARY_EXIT,
};
use ethlambda_types::beacon::containers::altair::{
    ContributionAndProof, SyncAggregatorSelectionData,
};
use ethlambda_types::beacon::containers::gloas::{
    ExecutionPayloadEnvelope, PayloadAttestationData, ProposerPreferences,
};
use ethlambda_types::beacon::containers::shared::{
    AttestationData, BeaconBlockHeader, Fork, VoluntaryExit,
};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::primitives::{
    BLS_SIGNATURE_SIZE, BlsPubkey, BlsSignature, Domain, DomainType, Epoch, HashTreeRoot as _,
    Root, Slot, Version,
};
// `AttestationData`, `Checkpoint`, `Fork` and `SigningData` all live in
// `containers::shared`, verified against `containers/shared.rs:158,120,97,220`.
use ethlambda_types::beacon::signing::{
    compute_builder_domain, compute_domain, compute_epoch_at_slot, compute_signing_root,
};

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
use tokio::sync::{RwLock, Semaphore};

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

/// Whether `signature` is `pubkey`'s signature over `root`. A pubkey or a
/// signature that is not a point on the curve verifies nothing.
fn verifies(pubkey: &BlsPubkey, root: Root, signature: &BlsSignature) -> bool {
    use blst::min_pk::{PublicKey, Signature};

    let (Ok(public_key), Ok(signature)) = (
        PublicKey::from_bytes(&pubkey.0),
        Signature::from_bytes(&signature.0),
    ) else {
        return false;
    };
    signature.verify(true, root.as_slice(), DST, &[], &public_key, true)
        == blst::BLST_ERROR::BLST_SUCCESS
}

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
    /// One permit per remote signature being verified; see [`Self::verified`].
    verifications: Arc<Semaphore>,
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
        // One verification per core: each is a pairing, pure CPU, so more at
        // once would only take turns on the same cores.
        let cores = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
        Self {
            config,
            genesis_validators_root,
            selection_proofs: Mutex::new(HashMap::new()),
            verifications: Arc::new(Semaphore::new(cores)),
        }
    }

    /// Whether `signature` is `pubkey`'s signature over `root`, checked on
    /// the blocking pool rather than on the task that asked.
    ///
    /// A verification is a pairing, about a millisecond of CPU with no await
    /// in it. Run inline, a batch's answers would be verified one after
    /// another on the duty task, where [`sign_all`]'s deadline cannot cut in:
    /// a thousand remote keys would hold the duty loop for a second or more
    /// that the signing budget does not bound, ahead of whatever the slot
    /// owes next. Here they run a core each, and waiting for a core is an
    /// await the budget covers.
    async fn verified(&self, pubkey: BlsPubkey, root: Root, signature: BlsSignature) -> bool {
        let Ok(permit) = self.verifications.clone().acquire_owned().await else {
            return false;
        };
        // The permit goes into the blocking task and is released when the
        // pairing ends, not when this future is dropped: a batch cut off at
        // its deadline leaves its verifications running, and they must still
        // count against the bound.
        let verification = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            verifies(&pubkey, root, &signature)
        });
        // A verification that did not run to its end vouches for nothing.
        verification.await.unwrap_or(false)
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

    /// The root a voluntary exit's signature is computed over.
    ///
    /// Every other signature here follows the fork at its message's own epoch.
    /// An exit follows the fork of the state that *processes* it, because that
    /// is the state a node verifies it against, and the two part ways as soon
    /// as an exit names an epoch from an earlier fork:
    ///
    /// - A deneb-or-later state verifies under `CAPELLA_FORK_VERSION` whatever
    ///   epoch the exit names (EIP-7044), so an exit signed now stays valid
    ///   across every fork to come. The point was pre-signed exits, which a
    ///   staking service hands its customer so they can leave without the
    ///   service's cooperation; a domain that moved with the schedule made
    ///   those expire at each fork.
    /// - An earlier state verifies under `get_domain(state,
    ///   DOMAIN_VOLUNTARY_EXIT, exit.epoch)`: its previous fork version for an
    ///   exit naming an epoch before its own fork, its current one otherwise.
    ///
    /// No state can process the exit before `max(current_epoch, exit.epoch)`:
    /// the chain is already at the one, and an exit is refused before the
    /// other. So the fork at that epoch is the one to sign for. Keying on
    /// `exit.epoch` alone, as Lighthouse does, signs an exit naming a
    /// pre-deneb epoch under that epoch's version, which no node on a chain
    /// past deneb accepts.
    pub fn voluntary_exit_signing_root(&self, exit: &VoluntaryExit, current_epoch: Epoch) -> Root {
        let domain = compute_domain(
            DOMAIN_VOLUNTARY_EXIT,
            self.voluntary_exit_fork_version(exit, current_epoch),
            self.genesis_validators_root,
        );
        compute_signing_root(exit.hash_tree_root(), domain)
    }

    /// The fork version `exit`'s domain is built from; the rule is spelled
    /// out on [`Self::voluntary_exit_signing_root`].
    fn voluntary_exit_fork_version(&self, exit: &VoluntaryExit, current_epoch: Epoch) -> Version {
        let fork = self.config.fork_at_epoch(current_epoch.max(exit.epoch));
        if fork >= ForkName::Deneb {
            self.config.capella_fork_version
        } else if exit.epoch < self.config.fork_epoch(fork) {
            self.config.fork_version(fork.previous().unwrap_or(fork))
        } else {
            self.config.fork_version(fork)
        }
    }

    /// The fork a remote signer is told `exit` is signed under: the one
    /// version its domain is built from, as both `previous` and `current`.
    ///
    /// Not [`Self::fork_info`] at the exit's epoch, which names the fork the
    /// schedule has there and so, from deneb on, a version the exit is not
    /// signed under. A signer derives the root itself from what it is told
    /// and refuses a request whose `signingRoot` disagrees, and Web3Signer
    /// has derived an exit's two ways: older releases pick the rule by the
    /// exit's epoch, current ones by this fork's epoch, and either then
    /// answers the capella version from its own configuration (deneb on) or
    /// picks `previous` or `current` by comparing the two epochs (before).
    /// With both versions the same, every one of those paths lands on the
    /// version this client signs under, whichever epoch the exit names.
    /// Lighthouse tells its signer the same thing for the same reason.
    fn voluntary_exit_fork_info(&self, exit: &VoluntaryExit, current_epoch: Epoch) -> ForkInfo {
        let version = self.voluntary_exit_fork_version(exit, current_epoch);
        ForkInfo {
            fork: Fork {
                previous_version: version,
                current_version: version,
                epoch: exit.epoch,
            },
            genesis_validators_root: self.genesis_validators_root,
        }
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
    async fn sign(
        &self,
        store: &RwLock<ValidatorStore>,
        pubkey: &BlsPubkey,
        root: Root,
        epoch: Epoch,
        body: SigningBody<'_>,
    ) -> Result<BlsSignature> {
        let fork_info = self.fork_info(epoch);
        self.sign_under(store, pubkey, root, epoch, fork_info, body)
            .await
    }

    /// [`Self::sign`], with the fork a remote signer is told given outright
    /// rather than read off the schedule at `epoch`. Only a voluntary exit
    /// needs that: every other message is domained by the fork at its own
    /// epoch.
    ///
    /// The store's read guard is held for the lookup alone and released before
    /// anything is signed. `tokio::sync::RwLock` is write-preferring, so a
    /// guard held across the remote signer's round trip would let one queued
    /// keymanager writer stall every other duty behind it for that long.
    async fn sign_under(
        &self,
        store: &RwLock<ValidatorStore>,
        pubkey: &BlsPubkey,
        root: Root,
        epoch: Epoch,
        fork_info: ForkInfo,
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
                let request = SigningRequest::new(fork_info, root, body);
                let signature = signer.sign(pubkey, &request).await?;
                // Checked before it leaves this function. The signer is
                // another process on the far side of a network: one holding a
                // different key under this pubkey, computing another root
                // for a fork it does not know, or answering through a proxy
                // that rewrote the body would otherwise have this client
                // publish a signature no peer accepts, and decide
                // `is_aggregator` on bytes that are not the selection proof.
                // A local key needs no such check: its signature is computed
                // here, over this root.
                if !self.verified(*pubkey, root, signature).await {
                    return Err(Error::Signing {
                        pubkey: *pubkey,
                        reason: format!(
                            "remote signer {} answered with a signature that does not verify \
                             for this key and message",
                            signer.url()
                        ),
                    });
                }
                Ok(signature)
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
    ///
    /// The store is asked before the memory is. A proof outlives its key
    /// there, so answering from it first would hand a key the keymanager
    /// deleted mid-epoch its selection: the aggregation would go on to fetch
    /// an aggregate it then cannot sign. A key this client no longer holds
    /// is [`Error::UnknownValidator`] here, as it is on every other path.
    pub async fn sign_selection_proof(
        &self,
        store: &RwLock<ValidatorStore>,
        pubkey: &BlsPubkey,
        slot: Slot,
    ) -> Result<BlsSignature> {
        if !store.read().await.contains(pubkey) {
            return Err(Error::UnknownValidator(*pubkey));
        }
        let remembered = self.selection_proofs().get(&(*pubkey, slot)).copied();
        if let Some(proof) = remembered {
            return Ok(proof);
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

    /// A builder registration's signature.
    ///
    /// Signed under `compute_builder_domain(genesis_fork_version)`: the genesis
    /// fork version and a zero validators root, per builder-specs, so a
    /// registration verifies whatever fork the chain is in. Not
    /// `DOMAIN_BEACON_BUILDER`, which is gloas's envelope domain. Not
    /// slashable: a registration commits to nothing about the chain, and a
    /// builder keeps only the newest one per validator.
    ///
    /// Synchronous and local keys only, through [`Self::sign_local`].
    /// Registrations are signed in bulk on the blocking pool, under a store
    /// read guard taken per chunk (see [`crate::registration`]), to keep
    /// thousands of signatures off the runtime; a remote signer's round trip
    /// has no place there. A key a Web3Signer holds goes unregistered: it gets
    /// no builder bid and its blocks are built locally, which costs no duty.
    pub fn sign_validator_registration(
        &self,
        store: &ValidatorStore,
        registration: &ValidatorRegistrationV1,
    ) -> Result<BlsSignature> {
        let domain = compute_builder_domain(self.config.genesis_fork_version);
        let root = compute_signing_root(registration.hash_tree_root(), domain);
        self.sign_local(store, &registration.pubkey, root, "builder registrations")
    }

    /// A proposer preferences message's signature, under
    /// `DOMAIN_PROPOSER_PREFERENCES` at the fork version of the proposal
    /// epoch itself.
    ///
    /// That is `get_signed_proposer_preferences` as of consensus-specs
    /// v1.7.0-beta.4, `compute_fork_version(proposal_epoch)` read off the
    /// schedule, and the `proposer_preferences` gossip rule verifies under the
    /// same domain. Every other client signs and verifies this way
    /// (Lighthouse, Prysm, Teku, Lodestar and Nimbus all take the fork of the
    /// proposal's epoch).
    ///
    /// The rule before it, beta.2's, verified with `get_domain` on the
    /// dependent block's state advanced to the lookahead start, which gives
    /// the fork of the epoch before the proposal's. That differs only for a
    /// proposal in the first epoch of a fork, and there Lighthouse refuses it
    /// as a bad signature: it did so for every first-gloas-epoch preference
    /// this client signed that way on a devnet. Not slashable.
    ///
    /// Synchronous and local keys only, through [`Self::sign_local`]: signed
    /// under the read guard [`crate::preferences`] holds for the batch. A key
    /// a Web3Signer holds publishes no preferences, so no builder bids for its
    /// slot and the node builds its payload locally, which costs no duty.
    pub fn sign_proposer_preferences(
        &self,
        store: &ValidatorStore,
        pubkey: &BlsPubkey,
        preferences: &ProposerPreferences,
    ) -> Result<BlsSignature> {
        let proposal_epoch = compute_epoch_at_slot(preferences.proposal_slot);
        let domain = self.domain(DOMAIN_PROPOSER_PREFERENCES, proposal_epoch);
        let root = compute_signing_root(preferences.hash_tree_root(), domain);
        self.sign_local(store, pubkey, root, "proposer preferences")
    }

    /// Sign `root` with `pubkey`'s key, which this process must hold.
    ///
    /// For the messages signed synchronously, under a store guard the caller
    /// already holds: builder registrations and proposer preferences. No
    /// remote signer request is defined for either here, so a key a
    /// Web3Signer holds is refused, `what` naming the message.
    fn sign_local(
        &self,
        store: &ValidatorStore,
        pubkey: &BlsPubkey,
        root: Root,
        what: &str,
    ) -> Result<BlsSignature> {
        match store
            .signer(pubkey)
            .ok_or(Error::UnknownValidator(*pubkey))?
        {
            SigningMethod::LocalKeystore { secret_key } => {
                let signature = secret_key.sign(root.as_slice(), DST, &[]);
                let bytes: [u8; BLS_SIGNATURE_SIZE] = signature.to_bytes();
                Ok(BlsSignature(bytes))
            }
            SigningMethod::Web3Signer { signer } => Err(Error::Signing {
                pubkey: *pubkey,
                reason: format!(
                    "{what} are not signed through a remote signer yet, so the key held by {} \
                     goes without",
                    signer.url()
                ),
            }),
        }
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

    /// Sign a voluntary exit on behalf of `pubkey`.
    ///
    /// Not slashable, and not guarded, but the one signature here that is
    /// **irreversible**: once the chain processes it the validator is on its
    /// way out, and nothing it signs afterwards brings it back. The guard is
    /// the caller's: the command line asks for a confirmation phrase, and the
    /// keymanager route is bearer-authenticated and only ever returns the
    /// signed message to its caller, which is what then decides to publish.
    ///
    /// `current_epoch` is the chain's, by the caller's clock; see
    /// [`Self::voluntary_exit_signing_root`] for why the domain needs it, and
    /// [`Self::voluntary_exit_fork_info`] for what a remote signer is told.
    pub async fn sign_voluntary_exit(
        &self,
        store: &RwLock<ValidatorStore>,
        pubkey: &BlsPubkey,
        exit: &VoluntaryExit,
        current_epoch: Epoch,
    ) -> Result<BlsSignature> {
        self.sign_under(
            store,
            pubkey,
            self.voluntary_exit_signing_root(exit, current_epoch),
            exit.epoch,
            self.voluntary_exit_fork_info(exit, current_epoch),
            SigningBody::VoluntaryExit {
                voluntary_exit: exit,
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
    /// evidence. Callers must have it allowed and recorded by
    /// [`crate::slashing_protection::SlashingProtection::check_and_record_block`]
    /// first.
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

    /// A remembered proof is for a validator this client serves. Once the
    /// keymanager has deleted the key its proofs answer nothing, so the
    /// aggregation stops at the selection rather than fetching an aggregate
    /// it then cannot sign.
    #[tokio::test]
    async fn a_remembered_selection_proof_is_not_handed_out_for_a_deleted_key() {
        let (store, pubkey) = store_with_key();
        let context = context();
        context
            .sign_selection_proof(&store, &pubkey, 3200)
            .await
            .expect("signs");

        assert!(store.write().await.remove(&pubkey));
        let err = context
            .sign_selection_proof(&store, &pubkey, 3200)
            .await
            .expect_err("the key is gone");
        assert!(matches!(err, Error::UnknownValidator(_)), "got {err:?}");
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

    fn registration(pubkey: BlsPubkey) -> ValidatorRegistrationV1 {
        ValidatorRegistrationV1 {
            fee_recipient: ethlambda_types::beacon::primitives::H160([0xab; 20]),
            gas_limit: 36_000_000,
            timestamp: 1_700_000_000,
            pubkey,
        }
    }

    /// A context whose genesis validators root is not zero, so the builder
    /// domain (which zeroes it) and a context-derived one cannot coincide.
    fn context_with_validators_root() -> SigningContext {
        SigningContext::new(Config::mainnet(), Root::repeat_byte(0x42))
    }

    #[test]
    fn a_registration_is_signed_under_the_builder_domain() {
        use ethlambda_types::beacon::constants::DOMAIN_APPLICATION_BUILDER;

        let (store, pubkey) = store_with_key();
        let context = context_with_validators_root();
        let registration = registration(pubkey);

        let signature = context
            .sign_validator_registration(&store.blocking_read(), &registration)
            .expect("signs");

        let root = compute_signing_root(
            registration.hash_tree_root(),
            compute_builder_domain(Config::mainnet().genesis_fork_version),
        );
        assert!(verify(&pubkey, &signature, root));

        // The same domain type under this chain's validators root is a
        // different domain: a context-derived one would not verify.
        let with_root = compute_signing_root(
            registration.hash_tree_root(),
            context.domain(DOMAIN_APPLICATION_BUILDER, 0),
        );
        assert!(!verify(&pubkey, &signature, with_root));
    }

    /// The registration domain is not gloas's envelope domain, whose type
    /// constant is similar in name only: a signature under one must not verify
    /// under the other.
    #[test]
    fn a_registration_does_not_verify_under_the_envelope_domain() {
        let (store, pubkey) = store_with_key();
        let context = context_with_validators_root();
        let registration = registration(pubkey);

        let signature = context
            .sign_validator_registration(&store.blocking_read(), &registration)
            .expect("signs");

        let envelope_root = compute_signing_root(
            registration.hash_tree_root(),
            context.domain(DOMAIN_BEACON_BUILDER, 0),
        );
        assert!(!verify(&pubkey, &signature, envelope_root));
    }

    /// The two synchronous messages are signed by local keys only: a key a
    /// Web3Signer holds is refused by name rather than sent a request no
    /// signer schema here defines.
    #[test]
    fn registrations_and_preferences_refuse_a_remote_key() {
        let pubkey = BlsPubkey([0xcd; 48]);
        let mut store = ValidatorStore::new();
        store
            .insert_remote(pubkey, "https://signer.example:9000")
            .expect("a well-formed signer url");
        let context = context_with_validators_root();

        let registration = context.sign_validator_registration(&store, &registration(pubkey));
        assert!(
            matches!(&registration, Err(Error::Signing { reason, .. }) if reason.contains("builder registrations")),
            "got {registration:?}"
        );
        let preferences = context.sign_proposer_preferences(&store, &pubkey, &preferences_for(64));
        assert!(
            matches!(&preferences, Err(Error::Signing { reason, .. }) if reason.contains("proposer preferences")),
            "got {preferences:?}"
        );
    }

    /// A config whose gloas fork starts at epoch 500000, fulu being active
    /// well before it, with a non-zero validators root.
    fn gloas_scheduled_context() -> (SigningContext, Epoch) {
        const GLOAS_EPOCH: Epoch = 500_000;
        let mut config = Config::mainnet();
        config.gloas_fork_epoch = GLOAS_EPOCH;
        (
            SigningContext::new(config, Root::repeat_byte(0x42)),
            GLOAS_EPOCH,
        )
    }

    fn preferences_for(slot: Slot) -> ProposerPreferences {
        ProposerPreferences {
            dependent_root: Root::repeat_byte(0x11),
            proposal_slot: slot,
            validator_index: 3,
            fee_recipient: ethlambda_types::beacon::primitives::H160([0xab; 20]),
            target_gas_limit: 36_000_000,
        }
    }

    /// Whether a preference for `slot`, signed by the client, verifies under
    /// fulu's and under gloas's version of `DOMAIN_PROPOSER_PREFERENCES`, in
    /// that order. The domains are spelled out rather than asked of
    /// [`SigningContext::domain`], so the test does not share the signer's
    /// choice of epoch.
    fn preference_verifies_under_fulu_and_gloas(slot: Slot) -> (bool, bool) {
        let (store, pubkey) = store_with_key();
        let (context, _) = gloas_scheduled_context();
        let preferences = preferences_for(slot);

        let signature = context
            .sign_proposer_preferences(&store.blocking_read(), &pubkey, &preferences)
            .expect("signs");

        let verifies_under = |version| {
            let domain = compute_domain(
                DOMAIN_PROPOSER_PREFERENCES,
                version,
                context.genesis_validators_root,
            );
            let root = compute_signing_root(preferences.hash_tree_root(), domain);
            verify(&pubkey, &signature, root)
        };
        (
            verifies_under(context.config.fulu_fork_version),
            verifies_under(context.config.gloas_fork_version),
        )
    }

    /// The first gloas epoch's preference is signed at gloas's version, the
    /// proposal epoch's own, which is what beta.4's gossip rule and every
    /// other client verify. Fulu's, the version beta.2's rule gave (the epoch
    /// before the proposal's), is what Lighthouse refused as a bad signature.
    #[test]
    fn a_preference_for_the_first_gloas_epoch_is_signed_under_the_gloas_version() {
        let (_, gloas_epoch) = gloas_scheduled_context();
        let slot = gloas_epoch * preset::SLOTS_PER_EPOCH + 2;

        let (under_fulu, under_gloas) = preference_verifies_under_fulu_and_gloas(slot);

        assert!(under_gloas, "the proposal epoch's version");
        assert!(!under_fulu, "not the version of the epoch before it");
    }

    /// One epoch later beta.2's rule gives gloas's version too, so the two
    /// rules agree from here on.
    #[test]
    fn a_preference_for_the_second_gloas_epoch_is_signed_under_the_gloas_version() {
        let (_, gloas_epoch) = gloas_scheduled_context();
        let slot = (gloas_epoch + 1) * preset::SLOTS_PER_EPOCH;

        let (under_fulu, under_gloas) = preference_verifies_under_fulu_and_gloas(slot);

        assert!(under_gloas);
        assert!(!under_fulu);
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

    /// The root an exit signs to under `version`, for the tests below.
    fn exit_root_under(context: &SigningContext, exit: &VoluntaryExit, version: [u8; 4]) -> Root {
        let domain = compute_domain(
            DOMAIN_VOLUNTARY_EXIT,
            version,
            context.genesis_validators_root,
        );
        compute_signing_root(exit.hash_tree_root(), domain)
    }

    #[tokio::test]
    async fn a_voluntary_exit_verifies_under_its_own_root() {
        let (store, pubkey) = store_with_key();
        let context = context();
        let exit = VoluntaryExit {
            epoch: context.config.deneb_fork_epoch + 10,
            validator_index: 42,
        };

        let signature = context
            .sign_voluntary_exit(&store, &pubkey, &exit, exit.epoch)
            .await
            .expect("signs");
        assert!(verify(
            &pubkey,
            &signature,
            context.voluntary_exit_signing_root(&exit, exit.epoch)
        ));
    }

    /// EIP-7044: from deneb on, an exit signs under the capella fork version
    /// and not the version of the fork its epoch is in. A client that used
    /// the schedule's version here would produce exits every deneb-or-later
    /// node rejects, and the operator would learn that from the node's 400.
    #[test]
    fn an_exit_at_or_after_deneb_signs_under_the_capella_fork_version() {
        let context = context();
        let far_beyond_deneb = context.config.electra_fork_epoch + 1_000;
        for epoch in [context.config.deneb_fork_epoch, far_beyond_deneb] {
            let exit = VoluntaryExit {
                epoch,
                validator_index: 1,
            };
            let expected = exit_root_under(&context, &exit, context.config.capella_fork_version);
            assert_eq!(context.voluntary_exit_signing_root(&exit, epoch), expected);
            assert_ne!(
                expected,
                compute_signing_root(
                    exit.hash_tree_root(),
                    context.domain(DOMAIN_VOLUNTARY_EXIT, epoch)
                ),
                "the fixture must cross a fork the schedule's version differs at"
            );
        }
    }

    /// The rule is the processing state's, not the exit's epoch's: a chain
    /// past deneb verifies every exit under the capella version, one naming
    /// epoch 0 included. Signing that one under the genesis version, which is
    /// what keying on `exit.epoch` did, produced an exit no node accepts.
    #[test]
    fn an_exit_naming_a_pre_deneb_epoch_signs_under_capella_on_a_chain_past_deneb() {
        let context = context();
        let config = &context.config;
        let now = config.electra_fork_epoch + 1_000;
        for epoch in [
            0,
            config.altair_fork_epoch,
            config.capella_fork_epoch + 1,
            config.deneb_fork_epoch - 1,
        ] {
            let exit = VoluntaryExit {
                epoch,
                validator_index: 1,
            };
            assert_eq!(
                context.voluntary_exit_signing_root(&exit, now),
                exit_root_under(&context, &exit, config.capella_fork_version),
                "exit epoch {epoch}"
            );
        }
        // A pre-signed exit for a deneb epoch, signed while the chain is still
        // before deneb, is processed by a deneb state too.
        let exit = VoluntaryExit {
            epoch: config.deneb_fork_epoch,
            validator_index: 1,
        };
        assert_eq!(
            context.voluntary_exit_signing_root(&exit, config.altair_fork_epoch),
            exit_root_under(&context, &exit, config.capella_fork_version)
        );
    }

    /// A remote signer derives an exit's root itself, from the fork it is
    /// told, and refuses a request whose `signingRoot` is another. So what it
    /// derives has to be the root this client signs, for every pairing of
    /// the exit's epoch and the chain's.
    ///
    /// `derived` is Teku's rule, which Web3Signer signs through: the capella
    /// version from deneb on, `get_domain` over the fork it was told before.
    /// Older releases pick between the two by the exit's epoch and current
    /// ones by the told fork's epoch; the fork told names the exit's epoch,
    /// so here the two readings are one.
    #[test]
    fn a_remote_signer_derives_the_exits_root_from_the_fork_it_is_told() {
        let context = context();
        let config = &context.config;
        let derived = |exit: &VoluntaryExit, told: &ForkInfo| {
            let version = if config.fork_at_epoch(told.fork.epoch) >= ForkName::Deneb {
                config.capella_fork_version
            } else if exit.epoch < told.fork.epoch {
                told.fork.previous_version
            } else {
                told.fork.current_version
            };
            exit_root_under(&context, exit, version)
        };

        let past_deneb = config.electra_fork_epoch + 1_000;
        let in_bellatrix = config.bellatrix_fork_epoch + 5;
        for (exit_epoch, current_epoch) in [
            // On a chain past deneb: the current epoch, epoch 0, and the last
            // epoch before deneb.
            (past_deneb, past_deneb),
            (0, past_deneb),
            (config.deneb_fork_epoch - 1, past_deneb),
            // Pre-signed for a deneb epoch while the chain is still before it.
            (config.deneb_fork_epoch, config.altair_fork_epoch),
            // On a chain before deneb: this fork, one fork back, two back.
            (in_bellatrix, in_bellatrix),
            (config.altair_fork_epoch + 1, in_bellatrix),
            (config.altair_fork_epoch - 1, in_bellatrix),
        ] {
            let exit = VoluntaryExit {
                epoch: exit_epoch,
                validator_index: 1,
            };
            let told = context.voluntary_exit_fork_info(&exit, current_epoch);
            assert_eq!(told.fork.epoch, exit.epoch);
            assert_eq!(
                derived(&exit, &told),
                context.voluntary_exit_signing_root(&exit, current_epoch),
                "exit epoch {exit_epoch} on a chain at epoch {current_epoch}"
            );
        }

        // What the schedule says at the exit's epoch is not it: from deneb on
        // that is a version no exit is signed under.
        let exit = VoluntaryExit {
            epoch: past_deneb,
            validator_index: 1,
        };
        assert_ne!(
            context.fork_info(exit.epoch).fork.current_version,
            context
                .voluntary_exit_fork_info(&exit, past_deneb)
                .fork
                .current_version
        );
    }

    /// Before deneb the ordinary rule held: the version of the fork at the
    /// exit's epoch, for an exit processed in that fork.
    #[test]
    fn an_exit_before_deneb_signs_under_its_epochs_fork_version() {
        let context = context();
        let exit = VoluntaryExit {
            epoch: context.config.altair_fork_epoch + 1,
            validator_index: 1,
        };
        assert_eq!(
            context.voluntary_exit_signing_root(&exit, exit.epoch),
            compute_signing_root(
                exit.hash_tree_root(),
                context.domain(DOMAIN_VOLUNTARY_EXIT, exit.epoch)
            )
        );
    }

    /// A pre-deneb state verifies through `get_domain`, which knows two
    /// versions: its own, and its previous one for any epoch before its fork.
    /// One fork back that is the exit's own version; two forks back it is not,
    /// and the chain's answer is the one to sign under.
    #[test]
    fn an_exit_before_deneb_signs_under_what_the_processing_state_verifies() {
        let context = context();
        let config = &context.config;
        let in_bellatrix = config.bellatrix_fork_epoch + 5;

        let one_fork_back = VoluntaryExit {
            epoch: config.altair_fork_epoch + 1,
            validator_index: 1,
        };
        assert_eq!(
            context.voluntary_exit_signing_root(&one_fork_back, in_bellatrix),
            exit_root_under(&context, &one_fork_back, config.altair_fork_version)
        );

        let two_forks_back = VoluntaryExit {
            epoch: config.altair_fork_epoch - 1,
            validator_index: 1,
        };
        assert_eq!(
            context.voluntary_exit_signing_root(&two_forks_back, in_bellatrix),
            exit_root_under(&context, &two_forks_back, config.altair_fork_version),
            "a bellatrix state's previous version is altair's, not genesis's"
        );
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
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        /// What the fake signer does: records every request and answers with
        /// a signature, or with a fixed status.
        #[derive(Clone)]
        struct Fake {
            requests: Arc<Mutex<Vec<(String, serde_json::Value)>>>,
            answer: Arc<Mutex<Answer>>,
            /// How many requests are being answered right now, and the most
            /// that ever were at once.
            in_flight: Arc<AtomicUsize>,
            peak: Arc<AtomicUsize>,
        }

        #[derive(Clone, Copy)]
        enum Answer {
            /// The test key's signature over the request's `signingRoot`, as
            /// a signer holding that key would give.
            Signature,
            /// The same, after a pause long enough for requests to overlap.
            SlowSignature,
            /// A well-formed signature over the request's `signingRoot`, by a
            /// key other than the one asked for.
            AnotherKeysSignature,
            /// The test key's signature, over a root other than the request's.
            AnotherRootsSignature,
            /// 96 bytes that are not a signature at all.
            Garbage,
            Status(u16),
        }

        /// `secret`'s signature over `root`, as hex.
        fn signature_hex(secret: &[u8; 32], root: &[u8]) -> String {
            let secret_key = blst::min_pk::SecretKey::from_bytes(secret).expect("a valid scalar");
            hex::encode(secret_key.sign(root, DST, &[]).to_bytes())
        }

        /// A second key, for a signer that answers with the wrong one.
        fn other_secret() -> [u8; 32] {
            let mut bytes = secret();
            bytes[31] ^= 0x01;
            bytes
        }

        async fn handle(
            State(fake): State<Fake>,
            Path(pubkey): Path<String>,
            body: String,
        ) -> (StatusCode, String) {
            let json: serde_json::Value = serde_json::from_str(&body).expect("json body");
            let root = hex::decode(
                json["signingRoot"]
                    .as_str()
                    .expect("a signing root")
                    .trim_start_matches("0x"),
            )
            .expect("hex");
            fake.requests.lock().expect("lock").push((pubkey, json));
            let signed = |signature: String| {
                (
                    StatusCode::OK,
                    format!("{{\"signature\":\"0x{signature}\"}}"),
                )
            };
            let answer = *fake.answer.lock().expect("lock");
            if matches!(answer, Answer::SlowSignature) {
                let now = fake.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                fake.peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(50)).await;
                fake.in_flight.fetch_sub(1, Ordering::SeqCst);
            }
            match answer {
                Answer::Signature | Answer::SlowSignature => {
                    signed(signature_hex(&secret(), &root))
                }
                Answer::AnotherKeysSignature => signed(signature_hex(&other_secret(), &root)),
                Answer::AnotherRootsSignature => signed(signature_hex(&secret(), &[0x11; 32])),
                Answer::Garbage => signed("ab".repeat(96)),
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
                in_flight: Arc::new(AtomicUsize::new(0)),
                peak: Arc::new(AtomicUsize::new(0)),
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

        /// A store whose one key, the test key's, is held by the signer at
        /// `url` and not by this process.
        fn remote_store(url: &str) -> (RwLock<ValidatorStore>, BlsPubkey) {
            let pubkey = ValidatorStore::derive_pubkey(&secret()).expect("a valid key");
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
            assert!(
                verify(&pubkey, &signature, context.attestation_signing_root(&data)),
                "the signer's signature is the one returned"
            );

            let requests = fake.requests.lock().expect("lock");
            assert_eq!(requests.len(), 1);
            let (path_pubkey, body) = &requests[0];
            assert_eq!(path_pubkey, &format!("0x{}", hex::encode(pubkey.0)));
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

        /// An exit for a key in a remote signer: the message travels in
        /// full, under the root this client derived, and the fork told is
        /// the capella version twice over (EIP-7044) rather than the fork
        /// the schedule has at the exit's epoch.
        #[tokio::test]
        async fn a_voluntary_exit_is_signed_by_the_remote_signer() {
            let (fake, url) = serve(Answer::Signature).await;
            let (store, pubkey) = remote_store(&url);
            let context = context();
            let now = context.config.electra_fork_epoch + 1_000;
            // Naming an epoch from before deneb, on a chain well past it.
            let exit = VoluntaryExit {
                epoch: context.config.altair_fork_epoch,
                validator_index: 42,
            };

            let signature = context
                .sign_voluntary_exit(&store, &pubkey, &exit, now)
                .await
                .expect("signs");
            let root = context.voluntary_exit_signing_root(&exit, now);
            assert!(verify(&pubkey, &signature, root));

            let requests = fake.requests.lock().expect("lock");
            assert_eq!(requests.len(), 1);
            let body = &requests[0].1;
            assert_eq!(body["type"], "VOLUNTARY_EXIT");
            assert_eq!(body["voluntary_exit"]["epoch"], exit.epoch.to_string());
            assert_eq!(body["voluntary_exit"]["validator_index"], "42");
            assert_eq!(
                body["signingRoot"],
                serde_json::to_value(root).expect("root")
            );
            let capella = serde_json::to_value(Fork {
                previous_version: context.config.capella_fork_version,
                current_version: context.config.capella_fork_version,
                epoch: exit.epoch,
            })
            .expect("fork");
            assert_eq!(body["fork_info"]["fork"], capella);
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

        /// What the signer answers is checked before it is used: a signature
        /// by another key, over another root, or that is no signature at all
        /// is a signing failure for that key, never something to publish.
        #[tokio::test]
        async fn a_signature_that_does_not_verify_is_a_signing_error() {
            for answer in [
                Answer::AnotherKeysSignature,
                Answer::AnotherRootsSignature,
                Answer::Garbage,
            ] {
                let (fake, url) = serve(answer).await;
                let (store, pubkey) = remote_store(&url);

                let err = context()
                    .sign_attestation(&store, &pubkey, &attestation_data(100))
                    .await
                    .expect_err("must fail");
                assert!(matches!(err, Error::Signing { .. }), "got {err:?}");
                assert!(err.to_string().contains("does not verify"), "{err}");
                assert!(!err.is_retryable());
                assert_eq!(fake.requests.lock().expect("lock").len(), 1, "asked once");
            }
        }

        /// The signer is asked for a selection proof once: the same key and
        /// slot again is answered from memory, another slot is another ask.
        #[tokio::test]
        async fn a_selection_proof_is_remembered_once_produced() {
            let (fake, url) = serve(Answer::Signature).await;
            let (store, pubkey) = remote_store(&url);
            let context = context();

            let first = context
                .sign_selection_proof(&store, &pubkey, 3200)
                .await
                .expect("signs");
            let again = context
                .sign_selection_proof(&store, &pubkey, 3200)
                .await
                .expect("remembered");
            assert_eq!(first, again);
            assert_eq!(fake.requests.lock().expect("lock").len(), 1, "asked once");

            context
                .sign_selection_proof(&store, &pubkey, 3201)
                .await
                .expect("signs");
            assert_eq!(
                fake.requests.lock().expect("lock").len(),
                2,
                "another slot is another proof"
            );
        }

        /// A batch larger than the signer's cap is sent a capful at a time,
        /// and every signature in it still arrives. Without the cap each
        /// request in flight is a socket of its own, and a thousand keys at
        /// an epoch boundary are a thousand sockets.
        #[tokio::test]
        async fn a_signer_is_never_sent_more_than_its_cap_at_once() {
            use crate::keys::Web3Signer;

            const CAP: usize = 4;
            const ASKED: usize = 4 * CAP;

            let (fake, url) = serve(Answer::SlowSignature).await;
            let pubkey = ValidatorStore::derive_pubkey(&secret()).expect("a valid key");
            let signer = Arc::new(Web3Signer::with_cap(&url, CAP).expect("a usable url"));
            let mut store = ValidatorStore::new();
            store.insert_remote_signer(pubkey, signer);
            let store = RwLock::new(store);
            let context = context();

            let proofs = sign_all((0..ASKED as Slot).map(|slot| {
                (
                    pubkey,
                    context.sign_selection_proof(&store, &pubkey, 3200 + slot),
                )
            }))
            .await;

            assert!(proofs.iter().all(Result::is_ok), "every proof arrives");
            assert_eq!(fake.requests.lock().expect("lock").len(), ASKED);
            assert_eq!(
                fake.peak.load(Ordering::SeqCst),
                CAP,
                "the batch fills the cap and never passes it"
            );
        }

        /// A selection proof that does not verify is not remembered: the
        /// next ask goes to the signer again rather than being answered from
        /// bytes that were never the proof.
        #[tokio::test]
        async fn an_unverified_selection_proof_is_not_remembered() {
            let (fake, url) = serve(Answer::AnotherKeysSignature).await;
            let (store, pubkey) = remote_store(&url);
            let context = context();

            context
                .sign_selection_proof(&store, &pubkey, 100)
                .await
                .expect_err("must fail");
            *fake.answer.lock().expect("lock") = Answer::Signature;
            let proof = context
                .sign_selection_proof(&store, &pubkey, 100)
                .await
                .expect("signs");
            assert!(verify(
                &pubkey,
                &proof,
                context.selection_proof_signing_root(100)
            ));
            assert_eq!(fake.requests.lock().expect("lock").len(), 2);
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
