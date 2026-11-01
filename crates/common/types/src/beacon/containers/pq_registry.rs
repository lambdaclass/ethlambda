//! EIP-8450's post-quantum key registry, borrowed out of a state that carries it.
//!
//! The registry is four lists parallel to the validator and builder registries.
//! Only heze's state has them, so the views come back as an option.
//! Code shared with gloas then asks the state, not the fork, whether there is a registry to update.

use libssz_types::ProgressiveList;

use super::BeaconState;
use super::heze::{
    BuilderPQKeyChangeEpochs, BuilderPQKeyMaterial, PQKeyMaterial, ValidatorPQKeyChangeEpochs,
    ValidatorPQKeyMaterial,
};
use crate::beacon::constants::{BUILDER_INDEX_FLAG, FAR_FUTURE_EPOCH};
use crate::beacon::error::{Error, Result};
use crate::beacon::primitives::{Epoch, ValidatorIndex, XmssPublicKey};

/// One registry entry: the stored keys, and the epoch of their last change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqEntry {
    /// The stored keys, all-zero for an index without registered keys.
    pub key_material: PQKeyMaterial,
    /// The epoch of the last change, or the index's never-registered marker.
    pub change_epoch: Epoch,
}

impl PqEntry {
    /// Whether the index has registered keys: its stored leanXMSS key is not all-zero.
    pub fn is_registered(&self) -> bool {
        !self.key_material.xmss_public_key.is_zero()
    }
}

/// The four registry lists of a state, read-only.
#[derive(Debug, Clone, Copy)]
pub struct PqRegistry<'a> {
    key_material: &'a ValidatorPQKeyMaterial,
    key_change_epochs: &'a ValidatorPQKeyChangeEpochs,
    builder_key_material: &'a BuilderPQKeyMaterial,
    builder_key_change_epochs: &'a BuilderPQKeyChangeEpochs,
}

impl PqRegistry<'_> {
    /// The entry of a validator, or none past the registry.
    pub fn validator(&self, index: ValidatorIndex) -> Option<PqEntry> {
        entry(self.key_material, self.key_change_epochs, index)
    }

    /// The entry of a builder, by builder index, or none past the registry.
    pub fn builder(&self, index: u64) -> Option<PqEntry> {
        entry(
            self.builder_key_material,
            self.builder_key_change_epochs,
            index,
        )
    }

    /// The entry of the registrant a registration's index names, or none past the registry.
    ///
    /// The builder flag bit tells a builder index from a validator index, as for withdrawals.
    pub fn registrant(&self, index: ValidatorIndex) -> Option<PqEntry> {
        if index & BUILDER_INDEX_FLAG != 0 {
            self.builder(index & !BUILDER_INDEX_FLAG)
        } else {
            self.validator(index)
        }
    }

    /// Whether any validator or builder currently holds the leanXMSS key.
    ///
    /// See `is_pq_public_key_in_use` in EIP-8450.
    ///
    /// # Performance
    ///
    /// A scan of both registries, as the EIP writes it.
    /// A block carries at most eight registrations, so it costs at most eight scans.
    pub fn is_key_in_use(&self, key: &XmssPublicKey) -> bool {
        self.key_material
            .iter()
            .chain(self.builder_key_material.iter())
            .any(|entry| entry.xmss_public_key == *key)
    }
}

/// The two parallel lists of one registry, read as one entry.
fn entry(key_material: &[PQKeyMaterial], change_epochs: &[Epoch], index: u64) -> Option<PqEntry> {
    let index = usize::try_from(index).ok()?;
    Some(PqEntry {
        key_material: *key_material.get(index)?,
        change_epoch: *change_epochs.get(index)?,
    })
}

/// The four registry lists of a state, writable.
#[derive(Debug)]
pub struct PqRegistryMut<'a> {
    key_material: &'a mut ValidatorPQKeyMaterial,
    key_change_epochs: &'a mut ValidatorPQKeyChangeEpochs,
    builder_key_material: &'a mut BuilderPQKeyMaterial,
    builder_key_change_epochs: &'a mut BuilderPQKeyChangeEpochs,
}

impl PqRegistryMut<'_> {
    /// The same lists, read-only.
    pub fn as_ref(&self) -> PqRegistry<'_> {
        PqRegistry {
            key_material: self.key_material,
            key_change_epochs: self.key_change_epochs,
            builder_key_material: self.builder_key_material,
            builder_key_change_epochs: self.builder_key_change_epochs,
        }
    }

    /// Appends the unset entry of a validator just appended to the registry.
    ///
    /// The entry holds the all-zero keys and the far future epoch.
    /// See the modified `add_validator_to_registry` in EIP-8450.
    pub fn push_validator(&mut self) {
        self.key_material.push(PQKeyMaterial::default());
        self.key_change_epochs.push(FAR_FUTURE_EPOCH);
    }

    /// Writes the unset entry of a builder placed at an index, appended or reused.
    ///
    /// The entry holds the all-zero keys, and the builder's deposit epoch as its marker.
    /// A reused index thereby drops the previous builder's keys.
    /// See the modified `add_builder_to_registry` in EIP-8450.
    ///
    /// # Errors
    ///
    /// Fails when the index is past the end, which no builder placement produces.
    pub fn reset_builder(&mut self, index: u64, deposit_epoch: Epoch) -> Result<()> {
        set_or_append(self.builder_key_material, index, PQKeyMaterial::default())?;
        set_or_append(self.builder_key_change_epochs, index, deposit_epoch)
    }

    /// Stores a validator's new keys and the epoch of the change.
    ///
    /// # Errors
    ///
    /// Fails when the index is past the registry.
    pub fn set_validator(
        &mut self,
        index: ValidatorIndex,
        key_material: PQKeyMaterial,
        epoch: Epoch,
    ) -> Result<()> {
        set(
            self.key_material,
            self.key_change_epochs,
            index,
            key_material,
            epoch,
        )
    }

    /// Stores a builder's new key and the epoch of the change.
    ///
    /// # Errors
    ///
    /// Fails when the index is past the registry.
    pub fn set_builder(
        &mut self,
        index: u64,
        key_material: PQKeyMaterial,
        epoch: Epoch,
    ) -> Result<()> {
        set(
            self.builder_key_material,
            self.builder_key_change_epochs,
            index,
            key_material,
            epoch,
        )
    }
}

/// Overwrites the element at an index, or appends it when the index is the length.
///
/// The specification's `set_or_append_list`.
fn set_or_append<T>(list: &mut ProgressiveList<T>, index: u64, value: T) -> Result<()> {
    let len = list.len();
    match usize::try_from(index) {
        Ok(position) if position < len => {
            list[position] = value;
            Ok(())
        }
        Ok(position) if position == len => {
            list.push(value);
            Ok(())
        }
        _ => Err(Error::IndexOutOfBounds {
            index: usize::try_from(index).unwrap_or(usize::MAX),
            len,
        }),
    }
}

/// Writes one entry of a pair of parallel lists.
fn set(
    key_material: &mut [PQKeyMaterial],
    change_epochs: &mut [Epoch],
    index: u64,
    material: PQKeyMaterial,
    epoch: Epoch,
) -> Result<()> {
    let len = key_material.len();
    let out_of_bounds = Error::IndexOutOfBounds {
        index: usize::try_from(index).unwrap_or(usize::MAX),
        len,
    };
    let Ok(position) = usize::try_from(index) else {
        return Err(out_of_bounds);
    };
    match (
        key_material.get_mut(position),
        change_epochs.get_mut(position),
    ) {
        (Some(stored_material), Some(stored_epoch)) => {
            *stored_material = material;
            *stored_epoch = epoch;
            Ok(())
        }
        _ => Err(out_of_bounds),
    }
}

impl BeaconState {
    /// The post-quantum key registry, or none for a fork without one.
    pub fn pq_registry(&self) -> Option<PqRegistry<'_>> {
        match self {
            BeaconState::Heze(state) => Some(PqRegistry {
                key_material: &state.post_quantum_key_material,
                key_change_epochs: &state.post_quantum_key_change_epochs,
                builder_key_material: &state.builder_post_quantum_key_material,
                builder_key_change_epochs: &state.builder_post_quantum_key_change_epochs,
            }),
            BeaconState::Phase0(_)
            | BeaconState::Altair(_)
            | BeaconState::Bellatrix(_)
            | BeaconState::Capella(_)
            | BeaconState::Deneb(_)
            | BeaconState::Electra(_)
            | BeaconState::Fulu(_)
            | BeaconState::Gloas(_)
            | BeaconState::Lean(_) => None,
        }
    }

    /// The post-quantum key registry, writable, or none for a fork without one.
    pub fn pq_registry_mut(&mut self) -> Option<PqRegistryMut<'_>> {
        match self {
            BeaconState::Heze(state) => Some(PqRegistryMut {
                key_material: &mut state.post_quantum_key_material,
                key_change_epochs: &mut state.post_quantum_key_change_epochs,
                builder_key_material: &mut state.builder_post_quantum_key_material,
                builder_key_change_epochs: &mut state.builder_post_quantum_key_change_epochs,
            }),
            BeaconState::Phase0(_)
            | BeaconState::Altair(_)
            | BeaconState::Bellatrix(_)
            | BeaconState::Capella(_)
            | BeaconState::Deneb(_)
            | BeaconState::Electra(_)
            | BeaconState::Fulu(_)
            | BeaconState::Gloas(_)
            | BeaconState::Lean(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::primitives::VrfRoot;

    fn keys(byte: u8) -> PQKeyMaterial {
        PQKeyMaterial {
            xmss_public_key: XmssPublicKey([byte; 32]),
            vrf_root: VrfRoot::repeat_byte(byte),
        }
    }

    #[test]
    fn set_or_append_overwrites_appends_or_refuses_a_gap() {
        // Fixture state: a builder list of two epochs, [3, 4].
        let mut epochs: ProgressiveList<Epoch> = vec![3, 4].into();

        // Index 1 is inside: overwritten.
        set_or_append(&mut epochs, 1, 9).unwrap();
        // Index 2 is the length: appended.
        set_or_append(&mut epochs, 2, 7).unwrap();
        assert_eq!(epochs.to_vec(), vec![3, 9, 7]);

        // Index 4 would leave a gap at 3: refused, the list untouched.
        assert!(matches!(
            set_or_append(&mut epochs, 4, 1),
            Err(Error::IndexOutOfBounds { index: 4, len: 3 })
        ));
        assert_eq!(epochs.to_vec(), vec![3, 9, 7]);
    }

    #[test]
    fn set_writes_both_lists_or_neither() {
        // Fixture state: two entries, both unset.
        let mut material = vec![PQKeyMaterial::default(); 2];
        let mut epochs = vec![FAR_FUTURE_EPOCH; 2];

        set(&mut material, &mut epochs, 1, keys(5), 20).unwrap();
        assert_eq!(material, vec![PQKeyMaterial::default(), keys(5)]);
        assert_eq!(epochs, vec![FAR_FUTURE_EPOCH, 20]);

        // Index 2 is past both lists: refused, nothing written.
        assert!(matches!(
            set(&mut material, &mut epochs, 2, keys(6), 21),
            Err(Error::IndexOutOfBounds { index: 2, len: 2 })
        ));
        assert_eq!(epochs, vec![FAR_FUTURE_EPOCH, 20]);
    }

    #[test]
    fn an_entry_is_registered_exactly_when_its_key_is_not_all_zero() {
        // The unset entry: all-zero keys, whatever its epoch marker.
        let unset = PqEntry {
            key_material: PQKeyMaterial::default(),
            change_epoch: FAR_FUTURE_EPOCH,
        };
        assert!(!unset.is_registered());

        // One nonzero byte in the key makes it registered.
        let mut key = [0; 32];
        key[31] = 1;
        let registered = PqEntry {
            key_material: PQKeyMaterial {
                xmss_public_key: XmssPublicKey(key),
                vrf_root: VrfRoot::ZERO,
            },
            change_epoch: 20,
        };
        assert!(registered.is_registered());
    }
}
