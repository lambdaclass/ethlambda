//! Producing the signatures a validator owes: attestations, the RANDAO reveal
//! a block carries, the block itself, and the two an aggregator needs.
//!
//! The signing root always comes from the SSZ container, never from the JSON a
//! beacon node sent: the wire representation is a transport detail, and the
//! chain only ever agrees about the merkle root.

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::constants::{
    DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_BUILDER,
    DOMAIN_BEACON_PROPOSER, DOMAIN_PTC_ATTESTER, DOMAIN_RANDAO, DOMAIN_SELECTION_PROOF,
};
use ethlambda_types::beacon::containers::gloas::{
    ExecutionPayloadEnvelope, PayloadAttestationData,
};
use ethlambda_types::beacon::containers::shared::AttestationData;
use ethlambda_types::beacon::primitives::{
    BLS_SIGNATURE_SIZE, BlsPubkey, BlsSignature, Domain, DomainType, Epoch, HashTreeRoot as _,
    Root, Slot,
};
// `AttestationData`, `Checkpoint`, `Fork` and `SigningData` all live in
// `containers::shared`, verified against `containers/shared.rs:158,120,97,220`.
use ethlambda_types::beacon::signing::{
    compute_domain, compute_epoch_at_slot, compute_signing_root,
};

use crate::error::{Error, Result};
use crate::keys::{SigningMethod, ValidatorStore};

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
}

impl SigningContext {
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

    /// Sign an already-computed signing root on behalf of `pubkey`.
    ///
    /// Every public signing method funnels through here, so there is one place
    /// a signature is actually produced and one place the remote-signer
    /// variant will need to be added. Deliberately private: a caller that can
    /// hand in an arbitrary root can make this client sign anything at all,
    /// and the domain separation that keeps an attestation from being read as
    /// a block lives in the callers above.
    fn sign_root(
        &self,
        store: &ValidatorStore,
        pubkey: &BlsPubkey,
        root: Root,
    ) -> Result<BlsSignature> {
        let method = store.get(pubkey).ok_or(Error::UnknownValidator(*pubkey))?;
        match method {
            SigningMethod::LocalKeystore { secret_key } => {
                let signature = secret_key.sign(root.as_slice(), DST, &[]);
                let bytes: [u8; BLS_SIGNATURE_SIZE] = signature.to_bytes();
                Ok(BlsSignature(bytes))
            }
        }
    }

    /// Sign `data` on behalf of `pubkey`.
    pub fn sign_attestation(
        &self,
        store: &ValidatorStore,
        pubkey: &BlsPubkey,
        data: &AttestationData,
    ) -> Result<BlsSignature> {
        self.sign_root(store, pubkey, self.attestation_signing_root(data))
    }

    /// Sign the RANDAO reveal for `epoch` on behalf of `pubkey`.
    ///
    /// Unlike the other two, this signature is not itself a slashable message:
    /// it commits to an epoch, not to a chain position, and producing one for
    /// an epoch a validator is not proposing in reveals nothing and risks
    /// nothing. It is therefore not guarded, and does not need to be.
    pub fn sign_randao(
        &self,
        store: &ValidatorStore,
        pubkey: &BlsPubkey,
        epoch: Epoch,
    ) -> Result<BlsSignature> {
        self.sign_root(store, pubkey, self.randao_signing_root(epoch))
    }

    /// Sign the selection proof for `slot` on behalf of `pubkey`.
    ///
    /// Not slashable, and not guarded. A selection proof commits to a slot, not
    /// to a chain position, so producing one twice is producing the same bytes
    /// twice: BLS signatures are deterministic, which is the property the
    /// selection rule rests on.
    pub fn sign_selection_proof(
        &self,
        store: &ValidatorStore,
        pubkey: &BlsPubkey,
        slot: Slot,
    ) -> Result<BlsSignature> {
        self.sign_root(store, pubkey, self.selection_proof_signing_root(slot))
    }

    /// Sign the aggregate whose `AggregateAndProof` root is `root`, for `slot`,
    /// on behalf of `pubkey`.
    ///
    /// Not slashable either, which is worth stating because it is the only
    /// signature here that covers an attestation and is not. The slashing
    /// conditions are about a validator's *own* vote; an aggregator is
    /// republishing other validators' votes with a wrapper saying who
    /// collected them, and publishing two different aggregates for one slot is
    /// wasteful rather than punishable.
    pub fn sign_aggregate_and_proof(
        &self,
        store: &ValidatorStore,
        pubkey: &BlsPubkey,
        root: Root,
        slot: Slot,
    ) -> Result<BlsSignature> {
        self.sign_root(
            store,
            pubkey,
            self.aggregate_and_proof_signing_root(root, slot),
        )
    }

    /// Sign the envelope revealing the payload of the block proposed for `slot`
    /// on behalf of `pubkey`, which for a self-built payload is the proposer's
    /// own key.
    ///
    /// Not slashable and not guarded. The specification attaches no slashing
    /// condition to an envelope: signing two for one slot is at worst a
    /// payload the network ignores one of. The block it belongs to is the
    /// guarded signature.
    pub fn sign_execution_payload_envelope(
        &self,
        store: &ValidatorStore,
        pubkey: &BlsPubkey,
        envelope: &ExecutionPayloadEnvelope,
        slot: Slot,
    ) -> Result<BlsSignature> {
        self.sign_root(store, pubkey, self.envelope_signing_root(envelope, slot))
    }

    /// Sign a payload timeliness committee vote on behalf of `pubkey`.
    ///
    /// Not slashable by the specification, and deduplicated per validator and
    /// slot by [`crate::payload_attestation`] only to avoid publishing the same
    /// vote twice.
    pub fn sign_payload_attestation(
        &self,
        store: &ValidatorStore,
        pubkey: &BlsPubkey,
        data: &PayloadAttestationData,
    ) -> Result<BlsSignature> {
        self.sign_root(store, pubkey, self.payload_attestation_signing_root(data))
    }

    /// Sign the block whose root is `block_root`, proposed for `slot`, on
    /// behalf of `pubkey`.
    ///
    /// This one *is* slashable, and is the most expensive signature this
    /// client can get wrong: two distinct blocks for one slot need no second
    /// validator to be caught, since the two signed headers are the whole
    /// evidence. Callers must pass it through
    /// [`crate::proposal_guard::ProposalGuard`] first.
    pub fn sign_block(
        &self,
        store: &ValidatorStore,
        pubkey: &BlsPubkey,
        block_root: Root,
        slot: Slot,
    ) -> Result<BlsSignature> {
        self.sign_root(store, pubkey, self.block_signing_root(block_root, slot))
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
        SigningContext {
            config: Config::mainnet(),
            genesis_validators_root: Root::ZERO,
        }
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

    #[test]
    fn a_signature_verifies_under_the_signing_root() {
        use blst::min_pk::{PublicKey, Signature};

        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        let context = context();
        let data = attestation_data(100);

        let signature = context
            .sign_attestation(&store, &pubkey, &data)
            .expect("signs");

        let root = context.attestation_signing_root(&data);
        let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
        let sig = Signature::from_bytes(&signature.0).expect("valid signature");
        assert_eq!(
            sig.verify(true, root.as_slice(), DST, &[], &pk, true),
            blst::BLST_ERROR::BLST_SUCCESS
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

    #[test]
    fn signing_for_an_unknown_validator_is_an_error() {
        let store = ValidatorStore::new();
        let err = context()
            .sign_attestation(&store, &BlsPubkey::default(), &attestation_data(1))
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

    fn store_with_key() -> (ValidatorStore, BlsPubkey) {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        (store, pubkey)
    }

    #[test]
    fn a_randao_reveal_verifies_under_the_randao_signing_root() {
        let (store, pubkey) = store_with_key();
        let context = context();

        let signature = context.sign_randao(&store, &pubkey, 100).expect("signs");
        assert!(verify(
            &pubkey,
            &signature,
            context.randao_signing_root(100)
        ));
    }

    #[test]
    fn a_block_signature_verifies_under_the_block_signing_root() {
        let (store, pubkey) = store_with_key();
        let context = context();
        let block_root = Root::repeat_byte(7);

        let signature = context
            .sign_block(&store, &pubkey, block_root, 3200)
            .expect("signs");
        assert!(verify(
            &pubkey,
            &signature,
            context.block_signing_root(block_root, 3200)
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

    #[test]
    fn signing_a_block_for_an_unknown_validator_is_an_error() {
        let store = ValidatorStore::new();
        let err = context()
            .sign_block(&store, &BlsPubkey::default(), Root::ZERO, 1)
            .expect_err("must fail");
        assert!(matches!(err, Error::UnknownValidator(_)), "got {err:?}");
    }

    #[test]
    fn a_selection_proof_verifies_under_its_own_root() {
        let (store, pubkey) = store_with_key();
        let context = context();

        let signature = context
            .sign_selection_proof(&store, &pubkey, 3200)
            .expect("signs");
        assert!(verify(
            &pubkey,
            &signature,
            context.selection_proof_signing_root(3200)
        ));
    }

    #[test]
    fn an_aggregate_signature_verifies_under_its_own_root() {
        let (store, pubkey) = store_with_key();
        let context = context();
        let root = Root::repeat_byte(4);

        let signature = context
            .sign_aggregate_and_proof(&store, &pubkey, root, 3200)
            .expect("signs");
        assert!(verify(
            &pubkey,
            &signature,
            context.aggregate_and_proof_signing_root(root, 3200)
        ));
    }

    #[test]
    fn signing_a_randao_reveal_for_an_unknown_validator_is_an_error() {
        let store = ValidatorStore::new();
        let err = context()
            .sign_randao(&store, &BlsPubkey::default(), 1)
            .expect_err("must fail");
        assert!(matches!(err, Error::UnknownValidator(_)), "got {err:?}");
    }
}
