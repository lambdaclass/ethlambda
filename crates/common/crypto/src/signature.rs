//! Validator XMSS signatures, public/secret keys, and the leanVM-backed
//! primitives behind them.

use std::ops::RangeInclusive;

use ethlambda_types::{attestation::SIGNATURE_SIZE, primitives::H256, state::PUBLIC_KEY_SIZE};
use leanvm::xmss::{
    self, Decode, Encode, LOG_LIFETIME, PUB_KEY_SSZ_LEN, SIGNATURE_SSZ_LEN, XmssKeyGenError,
    XmssPublicKey, XmssSecretKey, XmssSignError, XmssSignature,
};

// `ethlambda-types` hardcodes the XMSS wire sizes so it can stay free of the
// signing backend. This crate is the only place that sees both sides, so it is
// where they get pinned together: a leanVM bump that changes the scheme
// parameters fails to compile here instead of silently corrupting the wire
// format (every `XmssSignature` / `ValidatorPubkeyBytes` in `ethlambda-types` is
// sized by these constants).
//
// Written as an array-length mismatch rather than `assert!` so that rustc prints
// both evaluated sizes; a const panic message has to be a string literal and so
// cannot name the numbers that actually differ.
//
// When one of these fires, correct the constant in `ethlambda-types` to the size
// rustc reports. Do not take rustc's `help:` suggestion to edit the length on
// these lines, which only silences the check.
const _: [(); SIGNATURE_SIZE] = [(); SIGNATURE_SSZ_LEN];
const _: [(); PUBLIC_KEY_SIZE] = [(); PUB_KEY_SSZ_LEN];

/// Error returned when parsing signature or key bytes fails.
#[derive(Debug, Clone, thiserror::Error)]
#[error("signature parse error: {0}")]
pub struct SignatureParseError(pub String);

/// What the pinned leanVM's XMSS is, for a genesis key manifest to record.
///
/// A key set is only usable by a client built against the same scheme, and no
/// file size changes when the scheme does (leanVM's move from Poseidon over
/// KoalaBear to BLAKE2s over binary fields kept both wire sizes), so a manifest
/// has to say which scheme it holds rather than leave it to be inferred.
///
/// Only two of these fields are load-bearing. [`PUBLIC_KEY_BYTES`] and
/// [`LIFETIME`] come from leanVM and so cannot drift; the two labels are
/// hardcoded, because leanVM's facade exports neither a name for the hash nor
/// the `V`/`CHAIN_LENGTH` the scheme label is conventionally built from. That is
/// exactly why a manifest should also carry the leanVM revision, which is the
/// one field that identifies the format on its own.
pub mod scheme {
    use super::{LOG_LIFETIME, PUB_KEY_SSZ_LEN};

    /// The scheme label, in the form the genesis tooling has always read.
    ///
    /// `Dim`/`Base` are leanVM's `V` and `CHAIN_LENGTH`, neither re-exported;
    /// keep this in step with the pinned revision. Note that all three
    /// parameters survived the last change of hash function unchanged, so this
    /// label does NOT distinguish the two key formats by itself.
    pub const NAME: &str = "XmssTargetSumLifetime32Dim42Base8";

    /// The hash the scheme is built on. Hardcoded, as [`NAME`] is.
    pub const HASH_FUNCTION: &str = "BLAKE2s";

    /// The WOTS encoding: the signer grinds randomness until the digest's
    /// chunks sum to a fixed target, so there are no checksum chains.
    pub const ENCODING: &str = "TargetSum";

    /// Epochs a key could cover at most, whatever range it was generated for.
    pub const LIFETIME: u64 = 1 << LOG_LIFETIME;

    /// Bytes in an SSZ-encoded public key.
    pub const PUBLIC_KEY_BYTES: usize = PUB_KEY_SSZ_LEN;

    // [`NAME`] claims a 2^32 lifetime, which leanVM does export, so at least
    // that much of the hardcoded label is checked rather than trusted.
    const _: [(); 32] = [(); LOG_LIFETIME];
}

#[derive(Clone)]
pub struct ValidatorSignature {
    inner: XmssSignature,
}

impl ValidatorSignature {
    /// Parse from the SSZ-encoded wire form (`SIGNATURE_SIZE` bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureParseError> {
        let sig = XmssSignature::from_ssz_bytes(bytes)
            .map_err(|e| SignatureParseError(format!("{e:?}")))?;
        Ok(Self { inner: sig })
    }

    /// Encode to the SSZ wire form (`SIGNATURE_SIZE` bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_ssz_bytes()
    }

    pub fn is_valid(&self, pubkey: &ValidatorPublicKey, slot: u32, message: &H256) -> bool {
        xmss::verify(&pubkey.inner, &message.0, &self.inner, slot).is_ok()
    }

    pub fn into_inner(self) -> XmssSignature {
        self.inner
    }
}

// `Debug` only on the public key: the signature and the secret key carry
// material that must not reach a log line by accident.
#[derive(Clone, Debug)]
pub struct ValidatorPublicKey {
    inner: XmssPublicKey,
}

impl ValidatorPublicKey {
    /// Parse from the SSZ-encoded wire form (`PUBLIC_KEY_SIZE` bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureParseError> {
        let pk = XmssPublicKey::from_ssz_bytes(bytes)
            .map_err(|e| SignatureParseError(format!("{e:?}")))?;
        Ok(Self { inner: pk })
    }

    /// Encode to the SSZ wire form (`PUBLIC_KEY_SIZE` bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_ssz_bytes()
    }

    pub fn into_inner(self) -> XmssPublicKey {
        self.inner
    }

    pub fn as_inner(&self) -> &XmssPublicKey {
        &self.inner
    }
}

/// Validator private key for signing attestations and blocks.
pub struct ValidatorSecretKey {
    inner: XmssSecretKey,
}

impl ValidatorSecretKey {
    /// Generate a fresh key able to sign at each slot in `slots`, once.
    ///
    /// The range is inclusive and fixed for the key's life: a slot outside it
    /// can never be signed. Nothing can regenerate the key, the seed coming
    /// from the OS.
    ///
    /// Cost grows with the range, but sublinearly: leanVM stores
    /// `O(sqrt(range))` of the tree and fans key generation out over the bottom
    /// subtrees.
    pub fn generate(slots: RangeInclusive<u32>) -> Result<Self, XmssKeyGenError> {
        let (sk, _pk) = xmss::key_gen(&mut leanvm::rand::rng(), *slots.start(), *slots.end())?;
        Ok(Self { inner: sk })
    }

    /// Deterministic [`Self::generate`]: one `(seed, slots)` always rebuilds the
    /// same key, the seed being its entire secret material.
    pub fn generate_from_seed(
        seed: [u8; 32],
        slots: RangeInclusive<u32>,
    ) -> Result<Self, XmssKeyGenError> {
        let (sk, _pk) = xmss::key_gen_from_seed(seed, *slots.start(), *slots.end())?;
        Ok(Self { inner: sk })
    }

    /// Parse from the postcard-encoded key file produced by the genesis generator.
    ///
    /// leanVM's `XmssSecretKey` carries serde rather than an SSZ codec: the
    /// secret key never appears in consensus data, so only the two wire types
    /// get one.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureParseError> {
        let sk = postcard::from_bytes::<XmssSecretKey>(bytes)
            .map_err(|e| SignatureParseError(format!("{e:?}")))?;
        Ok(Self { inner: sk })
    }

    /// Serialize the secret key to its postcard key-file form.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SignatureParseError> {
        postcard::to_allocvec(&self.inner).map_err(|e| SignatureParseError(format!("{e:?}")))
    }

    /// The public key derived from this secret key.
    pub fn public_key(&self) -> ValidatorPublicKey {
        ValidatorPublicKey {
            inner: self.inner.public_key(),
        }
    }

    /// Sign a message at `slot`.
    ///
    /// The slot indexes the one-time XMSS leaf; never sign two different
    /// messages at the same slot. leanVM draws the signature randomness itself,
    /// so even re-signing the same message at one slot leaks key material.
    pub fn sign(&self, slot: u32, message: &H256) -> Result<ValidatorSignature, XmssSignError> {
        let sig = xmss::sign(&mut leanvm::rand::rng(), &self.inner, &message.0, slot)?;
        Ok(ValidatorSignature { inner: sig })
    }

    /// Whether the key covers `slot` at all.
    ///
    /// The range is fixed at key generation; a slot outside it can never be
    /// signed, however long the node waits.
    pub fn can_sign_at(&self, slot: u32) -> bool {
        self.inner.epoch_range().contains(&slot)
    }

    /// The inclusive slot range this key can sign for.
    pub fn signable_slots(&self) -> RangeInclusive<u32> {
        self.inner.epoch_range()
    }

    /// Warm the signing cache for `slot`, so [`Self::sign`] there does not pay
    /// for rebuilding the bottom Merkle subtree.
    ///
    /// The key holds one cached subtree, so this is worth calling only for the
    /// slot about to be signed, and it is pure latency shifting: a miss inside
    /// `sign` rebuilds the same subtree. Errors only when `slot` is outside
    /// [`Self::signable_slots`].
    pub fn prepare(&self, slot: u32) -> Result<(), XmssSignError> {
        self.inner.prepare(slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a validator key pair over a small slot range (fast key generation).
    fn generate_key(seed: [u8; 32], first_slot: u32, last_slot: u32) -> ValidatorSecretKey {
        ValidatorSecretKey::generate_from_seed(seed, first_slot..=last_slot)
            .expect("valid slot range")
    }

    /// The scheme label is what a key manifest is read back against, so a
    /// leanVM bump that moves a parameter has to move the label with it.
    #[test]
    fn scheme_reports_the_pinned_parameters() {
        assert_eq!(scheme::NAME, "XmssTargetSumLifetime32Dim42Base8");
        assert_eq!(scheme::PUBLIC_KEY_BYTES, PUBLIC_KEY_SIZE);
        assert_eq!(scheme::LIFETIME, 1 << 32);
    }

    /// A generated key has to survive the postcard round trip the node's key
    /// loader performs, and keep signing for the same public key.
    #[test]
    #[ignore = "slow: XMSS key generation and signing"]
    fn generated_key_round_trips_through_its_file_form() {
        let sk = ValidatorSecretKey::generate(0..=63).expect("valid slot range");
        let pk = sk.public_key();

        let reloaded = ValidatorSecretKey::from_bytes(&sk.to_bytes().expect("serializes"))
            .expect("its own file form parses");
        assert_eq!(reloaded.public_key().to_bytes(), pk.to_bytes());
        assert_eq!(reloaded.signable_slots(), sk.signable_slots());

        let message = H256::from([5u8; 32]);
        let signature = reloaded.sign(7, &message).expect("sign");
        assert!(signature.is_valid(&pk, 7, &message));
    }

    /// The seeded path is what makes a key set reproducible.
    #[test]
    #[ignore = "slow: XMSS key generation"]
    fn seeded_generation_is_deterministic() {
        let first = ValidatorSecretKey::generate_from_seed([11u8; 32], 0..=15).expect("range");
        let again = ValidatorSecretKey::generate_from_seed([11u8; 32], 0..=15).expect("range");
        let other = ValidatorSecretKey::generate_from_seed([12u8; 32], 0..=15).expect("range");

        assert_eq!(first.public_key().to_bytes(), again.public_key().to_bytes());
        assert_ne!(first.public_key().to_bytes(), other.public_key().to_bytes());
    }

    /// An inverted range has no epochs to sign at, so it is rejected rather
    /// than yielding a key that can do nothing.
    #[test]
    fn an_inverted_slot_range_is_rejected() {
        // Built from variables: as a literal, `10..=9` is a clippy error rather
        // than the input under test.
        let (first, last) = (10u32, 9u32);
        assert!(ValidatorSecretKey::generate_from_seed([0u8; 32], first..=last).is_err());
    }

    #[test]
    #[ignore = "slow: XMSS key generation and signing"]
    fn sign_verify_round_trip() {
        let sk = generate_key([7u8; 32], 0, 63);
        let pk = sk.public_key();

        assert!(sk.can_sign_at(0));
        assert!(sk.can_sign_at(63));
        assert!(!sk.can_sign_at(64));
        assert_eq!(sk.signable_slots(), 0..=63);

        let message = H256::from([42u8; 32]);
        let slot = 10u32;
        sk.prepare(slot).expect("slot in range");
        let sig = sk.sign(slot, &message).expect("sign");
        assert!(sig.is_valid(&pk, slot, &message));
        assert!(!sig.is_valid(&pk, slot, &H256::from([43u8; 32])));
        assert!(!sig.is_valid(&pk, slot + 1, &message));
    }

    #[test]
    #[ignore = "slow: XMSS key generation and signing"]
    fn sign_out_of_range_fails() {
        let sk = generate_key([9u8; 32], 100, 131);
        let message = H256::from([1u8; 32]);
        // Slot 0 is outside the key's range [100, 131].
        assert!(sk.sign(0, &message).is_err());
        assert!(sk.prepare(0).is_err());
    }

    #[test]
    #[ignore = "slow: XMSS key generation"]
    fn public_key_ssz_round_trip() {
        let sk = generate_key([3u8; 32], 0, 15);
        let pk = sk.public_key();
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), PUBLIC_KEY_SIZE);
        let parsed = ValidatorPublicKey::from_bytes(&bytes).expect("round trip");
        assert_eq!(parsed.to_bytes(), bytes);
    }
}
