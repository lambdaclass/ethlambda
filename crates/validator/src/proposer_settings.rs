//! What each validator proposes with: its fee recipient, graffiti and gas limit.
//!
//! Every validator starts on the process-wide defaults from the command line.
//! The keymanager API's `feerecipient`, `graffiti` and `gas_limit` endpoints
//! override them per key, and `DELETE` puts a key back on the defaults.
//!
//! # In memory only
//!
//! Overrides are not written anywhere, so a restart puts every validator back
//! on the defaults. Unlike an imported key, which must survive a restart or a
//! validator silently stops signing, an override that is lost is at worst a
//! block paying the default address or carrying the default text, and an
//! operator driving these endpoints can re-apply them after a restart.
//!
//! # When a change takes effect
//!
//! Graffiti and gas limit are read when they are used: the next proposal
//! carries the new value. A fee recipient reaches the beacon node through
//! `prepare_beacon_proposer`, which the duty loop sends once per epoch, so a
//! change is registered at the next epoch boundary. A block proposed before
//! then pays the address the node was last told, which the check before
//! signing reports as a mismatch.

use std::collections::HashMap;
use std::sync::{PoisonError, RwLock};

use ethlambda_types::beacon::primitives::{BlsPubkey, Bytes32, ExecutionAddress, H256};

/// A block's graffiti field is exactly this wide.
pub const GRAFFITI_BYTES: usize = 32;

/// `text` as a graffiti field: its UTF-8 bytes, right-padded with zeros.
///
/// `None` when it does not fit. Refused rather than truncated: a silently
/// clipped string appears in every block the validator proposes, where its
/// operator is least likely to look. Measured in bytes, which is what the field
/// holds, so a 32-character string of anything outside ASCII does not fit.
pub fn graffiti_from_text(text: &str) -> Option<Bytes32> {
    let text = text.as_bytes();
    if text.len() > GRAFFITI_BYTES {
        return None;
    }
    let mut bytes = [0u8; GRAFFITI_BYTES];
    bytes[..text.len()].copy_from_slice(text);
    Some(H256(bytes))
}

/// A graffiti field as text: the bytes before the trailing zeros, with
/// anything that is not UTF-8 replaced.
pub fn graffiti_to_text(graffiti: &Bytes32) -> String {
    let padding = graffiti
        .0
        .iter()
        .rev()
        .take_while(|byte| **byte == 0)
        .count();
    String::from_utf8_lossy(&graffiti.0[..GRAFFITI_BYTES - padding]).into_owned()
}

/// The gas limit a validator with no override reports.
///
/// Lighthouse's and Nimbus's default. Nothing in this client uses it yet: it
/// matters only to builder registrations, and there is no builder flow. It is
/// held so the keymanager API can serve it as the specification requires.
pub const DEFAULT_GAS_LIMIT: u64 = 60_000_000;

/// One validator's overrides; `None` means the default applies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Overrides {
    fee_recipient: Option<ExecutionAddress>,
    graffiti: Option<Bytes32>,
    gas_limit: Option<u64>,
}

impl Overrides {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Debug)]
struct Inner {
    default_fee_recipient: Option<ExecutionAddress>,
    default_graffiti: Bytes32,
    default_gas_limit: u64,
    overrides: HashMap<BlsPubkey, Overrides>,
}

/// The defaults and every per-key override, shared by the duty loop and the
/// keymanager API.
///
/// A `std::sync::RwLock` rather than an async one because no critical section
/// here awaits: each is one lookup or one insert.
///
/// A poisoned lock is recovered rather than propagated. The lock is poisoned
/// only by a panic while it is held, and every write is a single map
/// operation, so the data behind it is never left half-changed.
#[derive(Debug)]
pub struct ProposerSettings {
    inner: RwLock<Inner>,
}

impl ProposerSettings {
    /// Settings with no overrides, where every validator gets `graffiti` and
    /// `fee_recipient`.
    pub fn new(graffiti: Bytes32, fee_recipient: Option<ExecutionAddress>) -> Self {
        Self {
            inner: RwLock::new(Inner {
                default_fee_recipient: fee_recipient,
                default_graffiti: graffiti,
                default_gas_limit: DEFAULT_GAS_LIMIT,
                overrides: HashMap::new(),
            }),
        }
    }

    fn read<T>(&self, f: impl FnOnce(&Inner) -> T) -> T {
        f(&self.inner.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Apply `f` to `pubkey`'s overrides, dropping the entry once it holds
    /// none, so a key put back on every default leaves nothing behind.
    fn update(&self, pubkey: &BlsPubkey, f: impl FnOnce(&mut Overrides)) {
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        let entry = inner.overrides.entry(*pubkey).or_default();
        f(entry);
        if entry.is_empty() {
            inner.overrides.remove(pubkey);
        }
    }

    /// Where `pubkey`'s execution-layer rewards should go, or `None` when
    /// neither an override nor a default names an address.
    pub fn fee_recipient(&self, pubkey: &BlsPubkey) -> Option<ExecutionAddress> {
        self.read(|inner| {
            let overridden = inner.overrides.get(pubkey).and_then(|o| o.fee_recipient);
            overridden.or(inner.default_fee_recipient)
        })
    }

    /// The graffiti `pubkey` proposes with.
    pub fn graffiti(&self, pubkey: &BlsPubkey) -> Bytes32 {
        self.read(|inner| {
            let overridden = inner.overrides.get(pubkey).and_then(|o| o.graffiti);
            overridden.unwrap_or(inner.default_graffiti)
        })
    }

    /// The gas limit `pubkey` reports.
    pub fn gas_limit(&self, pubkey: &BlsPubkey) -> u64 {
        self.read(|inner| {
            let overridden = inner.overrides.get(pubkey).and_then(|o| o.gas_limit);
            overridden.unwrap_or(inner.default_gas_limit)
        })
    }

    pub fn set_fee_recipient(&self, pubkey: &BlsPubkey, address: ExecutionAddress) {
        self.update(pubkey, |entry| entry.fee_recipient = Some(address));
    }

    pub fn clear_fee_recipient(&self, pubkey: &BlsPubkey) {
        self.update(pubkey, |entry| entry.fee_recipient = None);
    }

    pub fn set_graffiti(&self, pubkey: &BlsPubkey, graffiti: Bytes32) {
        self.update(pubkey, |entry| entry.graffiti = Some(graffiti));
    }

    pub fn clear_graffiti(&self, pubkey: &BlsPubkey) {
        self.update(pubkey, |entry| entry.graffiti = None);
    }

    pub fn set_gas_limit(&self, pubkey: &BlsPubkey, gas_limit: u64) {
        self.update(pubkey, |entry| entry.gas_limit = Some(gas_limit));
    }

    pub fn clear_gas_limit(&self, pubkey: &BlsPubkey) {
        self.update(pubkey, |entry| entry.gas_limit = None);
    }

    /// Drop every override `pubkey` holds, for a key this client no longer
    /// signs with. A key imported again later starts on the defaults.
    pub fn forget(&self, pubkey: &BlsPubkey) {
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        inner.overrides.remove(pubkey);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::primitives::H160;

    fn key(byte: u8) -> BlsPubkey {
        BlsPubkey([byte; 48])
    }

    fn settings() -> ProposerSettings {
        ProposerSettings::new(Bytes32::repeat_byte(0x11), Some(H160([0xaa; 20])))
    }

    #[test]
    fn a_key_without_overrides_gets_the_defaults() {
        let settings = settings();
        assert_eq!(settings.fee_recipient(&key(1)), Some(H160([0xaa; 20])));
        assert_eq!(settings.graffiti(&key(1)), Bytes32::repeat_byte(0x11));
        assert_eq!(settings.gas_limit(&key(1)), DEFAULT_GAS_LIMIT);
    }

    #[test]
    fn an_override_applies_to_its_key_only() {
        let settings = settings();
        settings.set_fee_recipient(&key(1), H160([0xbb; 20]));
        settings.set_graffiti(&key(1), Bytes32::repeat_byte(0x22));
        settings.set_gas_limit(&key(1), 30_000_000);

        assert_eq!(settings.fee_recipient(&key(1)), Some(H160([0xbb; 20])));
        assert_eq!(settings.graffiti(&key(1)), Bytes32::repeat_byte(0x22));
        assert_eq!(settings.gas_limit(&key(1)), 30_000_000);

        assert_eq!(settings.fee_recipient(&key(2)), Some(H160([0xaa; 20])));
        assert_eq!(settings.graffiti(&key(2)), Bytes32::repeat_byte(0x11));
        assert_eq!(settings.gas_limit(&key(2)), DEFAULT_GAS_LIMIT);
    }

    /// Clearing one field leaves the others overridden.
    #[test]
    fn clearing_an_override_restores_that_default_only() {
        let settings = settings();
        settings.set_fee_recipient(&key(1), H160([0xbb; 20]));
        settings.set_graffiti(&key(1), Bytes32::repeat_byte(0x22));

        settings.clear_fee_recipient(&key(1));
        assert_eq!(settings.fee_recipient(&key(1)), Some(H160([0xaa; 20])));
        assert_eq!(settings.graffiti(&key(1)), Bytes32::repeat_byte(0x22));
    }

    /// A per-key address counts even with no process-wide default: it is how
    /// an operator who never passed `--suggested-fee-recipient` names one.
    #[test]
    fn an_override_needs_no_default_fee_recipient() {
        let settings = ProposerSettings::new(Bytes32::ZERO, None);
        assert_eq!(settings.fee_recipient(&key(1)), None);
        settings.set_fee_recipient(&key(1), H160([0xbb; 20]));
        assert_eq!(settings.fee_recipient(&key(1)), Some(H160([0xbb; 20])));
    }

    #[test]
    fn a_forgotten_key_is_back_on_every_default() {
        let settings = settings();
        settings.set_fee_recipient(&key(1), H160([0xbb; 20]));
        settings.set_graffiti(&key(1), Bytes32::repeat_byte(0x22));
        settings.set_gas_limit(&key(1), 30_000_000);

        settings.forget(&key(1));
        assert_eq!(settings.fee_recipient(&key(1)), Some(H160([0xaa; 20])));
        assert_eq!(settings.graffiti(&key(1)), Bytes32::repeat_byte(0x11));
        assert_eq!(settings.gas_limit(&key(1)), DEFAULT_GAS_LIMIT);
    }

    #[test]
    fn graffiti_text_round_trips_through_the_field() {
        let graffiti = graffiti_from_text("hello").expect("fits");
        assert_eq!(&graffiti.0[..5], b"hello");
        assert!(graffiti.0[5..].iter().all(|byte| *byte == 0));
        assert_eq!(graffiti_to_text(&graffiti), "hello");
        assert_eq!(graffiti_to_text(&Bytes32::ZERO), "");
    }

    #[test]
    fn graffiti_of_exactly_the_field_width_fits_and_one_byte_more_does_not() {
        assert!(graffiti_from_text(&"a".repeat(GRAFFITI_BYTES)).is_some());
        assert!(graffiti_from_text(&"a".repeat(GRAFFITI_BYTES + 1)).is_none());
        // Sixteen two-byte characters fill the field; seventeen do not.
        assert!(graffiti_from_text(&"ñ".repeat(16)).is_some());
        assert!(graffiti_from_text(&"ñ".repeat(17)).is_none());
    }

    #[test]
    fn a_key_cleared_of_every_override_leaves_no_entry() {
        let settings = settings();
        settings.set_graffiti(&key(1), Bytes32::repeat_byte(0x22));
        settings.clear_graffiti(&key(1));
        assert!(settings.read(|inner| inner.overrides.is_empty()));
    }
}
