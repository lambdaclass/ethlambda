//! What each validator proposes with: its fee recipient, graffiti and gas limit.
//!
//! Every validator starts on the process-wide defaults from the command line.
//! The keymanager API's `feerecipient`, `graffiti` and `gas_limit` endpoints
//! override them per key, and `DELETE` puts a key back on the defaults.
//!
//! # The definitions file is the record; this is the cache
//!
//! Each override is persisted on its validator's entry in
//! `validator_definitions.yml` (`suggested_fee_recipient`, `graffiti`,
//! `gas_limit`, Lighthouse's layout, so a file written by either client reads
//! in the other). The keymanager writes the file before it changes anything
//! here, and startup seeds this from the file, so what an operator set is what
//! the next restart runs with. An operator may also put the fields in the file
//! by hand before starting the client.
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{PoisonError, RwLock};

use ethlambda_types::beacon::primitives::{BlsPubkey, Bytes32, ExecutionAddress, H160, H256};

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
/// Lighthouse's and Nimbus's default. Builder registrations carry it as the
/// gas limit the builder should target, and the keymanager API serves it as the
/// specification requires.
pub const DEFAULT_GAS_LIMIT: u64 = 60_000_000;

/// `text` as a fee recipient: `0x` and forty hex digits, the keymanager
/// specification's `EthAddress` pattern. The zero address is refused: the
/// specification forbids it outright, since it would read as an address
/// chosen on purpose and pays nobody.
pub fn fee_recipient_from_text(text: &str) -> Result<ExecutionAddress, String> {
    let Some(digits) = text.strip_prefix("0x") else {
        return Err("must be 0x-prefixed hex".to_string());
    };
    let bytes = hex::decode(digits).map_err(|err| format!("is not hex: {err}"))?;
    let bytes: [u8; ADDRESS_BYTES] = bytes
        .try_into()
        .map_err(|got: Vec<u8>| format!("is {} bytes, expected {ADDRESS_BYTES}", got.len()))?;
    if bytes == [0; ADDRESS_BYTES] {
        return Err("is the zero address, which cannot be a fee recipient".to_string());
    }
    Ok(H160(bytes))
}

/// A fee recipient as the `0x`-prefixed hex the file and the API carry.
pub fn fee_recipient_to_text(address: &ExecutionAddress) -> String {
    format!("0x{}", hex::encode(address.0))
}

/// An execution address is exactly this wide.
pub const ADDRESS_BYTES: usize = 20;

/// One validator's overrides; `None` means the default applies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Overrides {
    pub fee_recipient: Option<ExecutionAddress>,
    pub graffiti: Option<Bytes32>,
    pub gas_limit: Option<u64>,
}

impl Overrides {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// `change` applied on top of these.
    pub fn apply(&mut self, change: SettingChange) {
        match change {
            SettingChange::FeeRecipient(address) => self.fee_recipient = address,
            SettingChange::Graffiti(graffiti) => self.graffiti = graffiti,
            SettingChange::GasLimit(gas_limit) => self.gas_limit = gas_limit,
        }
    }
}

/// One change to one validator's overrides: a new value, or `None` to put
/// that setting back on the default. One type for the three, so the
/// keymanager's persist-then-apply step is written once rather than six times.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingChange {
    FeeRecipient(Option<ExecutionAddress>),
    Graffiti(Option<Bytes32>),
    GasLimit(Option<u64>),
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
    /// Bumped on every override write or delete, so a reader that caches
    /// something derived from the settings (the builder registrations) can
    /// tell that nothing changed without reading every key.
    generation: AtomicU64,
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
            generation: AtomicU64::new(0),
        }
    }

    /// A counter that moves whenever any override is written, cleared or
    /// forgotten. Equal readings mean no per-key setting changed between them.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
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
        // Inside the write lock, so a reader that sees the new generation also
        // sees the new value.
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// Where `pubkey`'s execution-layer rewards should go, or `None` when
    /// neither an override nor a default names an address.
    pub fn fee_recipient(&self, pubkey: &BlsPubkey) -> Option<ExecutionAddress> {
        self.read(|inner| {
            let overridden = inner.overrides.get(pubkey).and_then(|o| o.fee_recipient);
            overridden.or(inner.default_fee_recipient)
        })
    }

    /// `pubkey`'s fee recipient and gas limit read together, under one lock, or
    /// `None` when it has no fee recipient.
    ///
    /// For a signed message that carries both (a builder registration, proposer
    /// preferences): two separate reads could straddle a keymanager write and
    /// pair an old address with a new gas limit, a combination the operator
    /// never configured, which the builder then keeps.
    pub fn fee_recipient_and_gas_limit(
        &self,
        pubkey: &BlsPubkey,
    ) -> Option<(ExecutionAddress, u64)> {
        self.read(|inner| {
            let overrides = inner.overrides.get(pubkey);
            let fee_recipient = overrides
                .and_then(|o| o.fee_recipient)
                .or(inner.default_fee_recipient)?;
            let gas_limit = overrides
                .and_then(|o| o.gas_limit)
                .unwrap_or(inner.default_gas_limit);
            Some((fee_recipient, gas_limit))
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

    /// Every override `pubkey` holds, defaults left as `None`.
    pub fn overrides(&self, pubkey: &BlsPubkey) -> Overrides {
        self.read(|inner| inner.overrides.get(pubkey).copied().unwrap_or_default())
    }

    /// Apply one change to `pubkey`'s overrides. The keymanager calls this
    /// only after the same change is in the definitions file.
    pub fn apply(&self, pubkey: &BlsPubkey, change: SettingChange) {
        self.update(pubkey, |entry| entry.apply(change));
    }

    /// Install `pubkey`'s overrides wholesale, replacing any it had. What
    /// startup does with each entry read from the definitions file.
    pub fn seed(&self, pubkey: &BlsPubkey, overrides: Overrides) {
        self.update(pubkey, |entry| *entry = overrides);
    }

    pub fn set_fee_recipient(&self, pubkey: &BlsPubkey, address: ExecutionAddress) {
        self.apply(pubkey, SettingChange::FeeRecipient(Some(address)));
    }

    pub fn clear_fee_recipient(&self, pubkey: &BlsPubkey) {
        self.apply(pubkey, SettingChange::FeeRecipient(None));
    }

    pub fn set_graffiti(&self, pubkey: &BlsPubkey, graffiti: Bytes32) {
        self.apply(pubkey, SettingChange::Graffiti(Some(graffiti)));
    }

    pub fn clear_graffiti(&self, pubkey: &BlsPubkey) {
        self.apply(pubkey, SettingChange::Graffiti(None));
    }

    pub fn set_gas_limit(&self, pubkey: &BlsPubkey, gas_limit: u64) {
        self.apply(pubkey, SettingChange::GasLimit(Some(gas_limit)));
    }

    pub fn clear_gas_limit(&self, pubkey: &BlsPubkey) {
        self.apply(pubkey, SettingChange::GasLimit(None));
    }

    /// Drop every override `pubkey` holds, for a key this client no longer
    /// signs with. A key imported again later starts on the defaults.
    pub fn forget(&self, pubkey: &BlsPubkey) {
        let mut inner = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        inner.overrides.remove(pubkey);
        self.generation.fetch_add(1, Ordering::Release);
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

    /// The pair a signed registration or preference carries agrees with the
    /// two separate reads, and is `None` exactly when there is no address.
    #[test]
    fn the_fee_recipient_and_gas_limit_read_together_match_the_single_reads() {
        let settings = ProposerSettings::new(Bytes32::ZERO, None);
        assert_eq!(settings.fee_recipient_and_gas_limit(&key(1)), None);

        settings.set_gas_limit(&key(1), 30_000_000);
        assert_eq!(settings.fee_recipient_and_gas_limit(&key(1)), None);
        settings.set_fee_recipient(&key(1), H160([0xbb; 20]));
        assert_eq!(
            settings.fee_recipient_and_gas_limit(&key(1)),
            Some((H160([0xbb; 20]), 30_000_000))
        );

        let defaults = self::settings();
        assert_eq!(
            defaults.fee_recipient_and_gas_limit(&key(2)),
            Some((H160([0xaa; 20]), DEFAULT_GAS_LIMIT))
        );
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
    fn seeding_replaces_a_keys_overrides_wholesale() {
        let settings = settings();
        settings.set_gas_limit(&key(1), 30_000_000);
        settings.seed(
            &key(1),
            Overrides {
                fee_recipient: Some(H160([0xbb; 20])),
                graffiti: None,
                gas_limit: None,
            },
        );
        assert_eq!(settings.fee_recipient(&key(1)), Some(H160([0xbb; 20])));
        assert_eq!(
            settings.gas_limit(&key(1)),
            DEFAULT_GAS_LIMIT,
            "an override the seed does not carry is gone"
        );
        settings.seed(&key(1), Overrides::default());
        assert!(settings.read(|inner| inner.overrides.is_empty()));
    }

    #[test]
    fn a_fee_recipient_round_trips_through_text_and_the_zero_address_is_refused() {
        let text = format!("0x{}", "ab".repeat(ADDRESS_BYTES));
        let address = fee_recipient_from_text(&text).expect("valid");
        assert_eq!(address, H160([0xab; ADDRESS_BYTES]));
        assert_eq!(fee_recipient_to_text(&address), text);
        for bad in [
            "ab".repeat(ADDRESS_BYTES),
            format!("0x{}", "ab".repeat(ADDRESS_BYTES - 1)),
            format!("0x{}", "zz".repeat(ADDRESS_BYTES)),
            format!("0x{}", "00".repeat(ADDRESS_BYTES)),
        ] {
            assert!(fee_recipient_from_text(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_key_cleared_of_every_override_leaves_no_entry() {
        let settings = settings();
        settings.set_graffiti(&key(1), Bytes32::repeat_byte(0x22));
        settings.clear_graffiti(&key(1));
        assert!(settings.read(|inner| inner.overrides.is_empty()));
    }
}
