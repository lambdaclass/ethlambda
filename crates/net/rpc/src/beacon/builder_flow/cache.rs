//! The registrations this node forwarded to its builder, so block
//! production knows which proposers use the builder, and with what gas
//! limit.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ethlambda_types::beacon::builder::ValidatorRegistrationV1;
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch};

/// How many epochs a registration lasts without being sent again. Validator
/// clients resend theirs every epoch, so two missed epochs mean the client
/// stopped using the builder, or stopped.
pub(crate) const REGISTRATION_LIFETIME_EPOCHS: Epoch = 2;

/// Each validator's latest registration, keyed by its pubkey.
#[derive(Debug, Clone, Default)]
pub(crate) struct BuilderRegistrations(Arc<Mutex<HashMap<BlsPubkey, Entry>>>);

#[derive(Debug, Clone)]
struct Entry {
    registration: ValidatorRegistrationV1,
    /// The epoch it was last sent in.
    seen: Epoch,
}

impl BuilderRegistrations {
    /// Records `registrations`, sent in `epoch`.
    ///
    /// One with an older timestamp than the registration held is ignored, as
    /// builders ignore it; any other replaces it and restarts its lifetime.
    /// Expired entries are dropped on the way, which bounds the map by the
    /// registrations still being sent.
    pub(crate) fn record<'a>(
        &self,
        registrations: impl IntoIterator<Item = &'a ValidatorRegistrationV1>,
        epoch: Epoch,
    ) {
        let mut entries = self.0.lock().expect("builder registrations lock poisoned");
        entries.retain(|_, entry| !expired(entry, epoch));
        for registration in registrations {
            match entries.get_mut(&registration.pubkey) {
                Some(entry) if registration.timestamp < entry.registration.timestamp => {}
                Some(entry) => {
                    entry.registration = registration.clone();
                    entry.seen = epoch;
                }
                None => {
                    let entry = Entry {
                        registration: registration.clone(),
                        seen: epoch,
                    };
                    entries.insert(registration.pubkey, entry);
                }
            }
        }
    }

    /// `pubkey`'s registration, if it is still current at `epoch`.
    pub(crate) fn get(&self, pubkey: &BlsPubkey, epoch: Epoch) -> Option<ValidatorRegistrationV1> {
        let entries = self.0.lock().expect("builder registrations lock poisoned");
        entries
            .get(pubkey)
            .filter(|entry| !expired(entry, epoch))
            .map(|entry| entry.registration.clone())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

fn expired(entry: &Entry, epoch: Epoch) -> bool {
    epoch > entry.seen.saturating_add(REGISTRATION_LIFETIME_EPOCHS)
}

#[cfg(test)]
mod tests {
    use ethlambda_types::beacon::primitives::ExecutionAddress;

    use super::*;

    fn registration(key: u8, timestamp: u64, gas_limit: u64) -> ValidatorRegistrationV1 {
        ValidatorRegistrationV1 {
            fee_recipient: ExecutionAddress::repeat_byte(key),
            gas_limit,
            timestamp,
            pubkey: BlsPubkey([key; 48]),
        }
    }

    #[test]
    fn a_registration_lasts_two_epochs_without_a_resend() {
        let cache = BuilderRegistrations::default();
        let held = registration(1, 100, 30_000_000);
        cache.record([&held], 10);
        assert_eq!(cache.get(&held.pubkey, 12), Some(held.clone()));
        assert_eq!(cache.get(&held.pubkey, 13), None);
    }

    #[test]
    fn a_resend_restarts_the_lifetime() {
        let cache = BuilderRegistrations::default();
        let held = registration(1, 100, 30_000_000);
        cache.record([&held], 10);
        cache.record([&held], 12);
        assert_eq!(cache.get(&held.pubkey, 14), Some(held));
    }

    #[test]
    fn a_newer_registration_replaces_the_held_one() {
        let cache = BuilderRegistrations::default();
        let old = registration(1, 100, 30_000_000);
        let new = registration(1, 200, 60_000_000);
        cache.record([&old], 10);
        cache.record([&new], 10);
        assert_eq!(cache.get(&old.pubkey, 10), Some(new));
    }

    #[test]
    fn an_older_registration_is_ignored_and_does_not_refresh() {
        let cache = BuilderRegistrations::default();
        let held = registration(1, 200, 60_000_000);
        let stale = registration(1, 100, 30_000_000);
        cache.record([&held], 10);
        cache.record([&stale], 12);
        assert_eq!(cache.get(&held.pubkey, 12), Some(held.clone()));
        assert_eq!(cache.get(&held.pubkey, 13), None);
    }

    #[test]
    fn expired_entries_are_dropped_on_the_next_record() {
        let cache = BuilderRegistrations::default();
        cache.record([&registration(1, 100, 1)], 10);
        cache.record([&registration(2, 100, 1)], 20);
        assert_eq!(cache.len(), 1);
    }
}
