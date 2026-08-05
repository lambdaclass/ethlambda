use serde::Deserialize;

use crate::state::{State, Validator, ValidatorPubkeyBytes};

/// Ways a state can fail to belong to the configured genesis.
///
/// Raised for any state whose provenance we have not established ourselves:
/// one downloaded through checkpoint sync, or one loaded from a data directory
/// that may have been written by a different network.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GenesisMismatch {
    #[error("genesis time mismatch: expected {expected}, got {got}")]
    GenesisTime { expected: u64, got: u64 },
    #[error("validator count mismatch: expected {expected}, got {got}")]
    ValidatorCount { expected: usize, got: usize },
    #[error(
        "validator at position {position} has non-sequential index (expected {position}, got {got})"
    )]
    NonSequentialIndex { position: usize, got: u64 },
    #[error("validator {index} pubkey mismatch (attestation or proposal key)")]
    ValidatorPubkey { index: usize },
}

/// A single validator entry in the genesis config with dual public keys.
#[derive(Debug, Clone, Deserialize)]
pub struct GenesisValidatorEntry {
    #[serde(deserialize_with = "deser_pubkey_hex")]
    pub attestation_pubkey: ValidatorPubkeyBytes,
    #[serde(deserialize_with = "deser_pubkey_hex")]
    pub proposal_pubkey: ValidatorPubkeyBytes,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GenesisConfig {
    #[serde(rename = "GENESIS_TIME")]
    pub genesis_time: u64,
    #[serde(rename = "GENESIS_VALIDATORS")]
    pub genesis_validators: Vec<GenesisValidatorEntry>,
}

impl GenesisConfig {
    pub fn validators(&self) -> Vec<Validator> {
        self.genesis_validators
            .iter()
            .enumerate()
            .map(|(i, entry)| Validator {
                attestation_pubkey: entry.attestation_pubkey,
                proposal_pubkey: entry.proposal_pubkey,
                index: i as u64,
            })
            .collect()
    }

    /// Verify `state` was produced by this genesis.
    ///
    /// Compares the genesis time and the full validator registry: count,
    /// sequential indices, and both pubkeys per validator. The validator set is
    /// fixed at genesis (nothing in the state transition mutates it), so any
    /// state of a chain started from this config must carry exactly this
    /// registry, whatever slot it sits at.
    ///
    /// This is a network-identity check, not a consistency check: it says
    /// nothing about whether the state is internally coherent. Callers that
    /// accept a state from an untrusted source pair it with their own sanity
    /// checks.
    pub fn verify_state(&self, state: &State) -> Result<(), GenesisMismatch> {
        verify_state_genesis(state, self.genesis_time, &self.validators())
    }
}

/// Verify `state` was produced by the genesis described by `genesis_time` and
/// `expected_validators`.
///
/// The implementation behind [`GenesisConfig::verify_state`], for callers that
/// hold the genesis time and validator registry separately rather than as a
/// parsed config.
pub fn verify_state_genesis(
    state: &State,
    genesis_time: u64,
    expected_validators: &[Validator],
) -> Result<(), GenesisMismatch> {
    if state.config.genesis_time != genesis_time {
        return Err(GenesisMismatch::GenesisTime {
            expected: genesis_time,
            got: state.config.genesis_time,
        });
    }

    if state.validators.len() != expected_validators.len() {
        return Err(GenesisMismatch::ValidatorCount {
            expected: expected_validators.len(),
            got: state.validators.len(),
        });
    }

    let pairs = state.validators.iter().zip(expected_validators.iter());
    for (position, (actual, expected)) in pairs.enumerate() {
        if actual.index != position as u64 {
            return Err(GenesisMismatch::NonSequentialIndex {
                position,
                got: actual.index,
            });
        }
        if actual.attestation_pubkey != expected.attestation_pubkey
            || actual.proposal_pubkey != expected.proposal_pubkey
        {
            return Err(GenesisMismatch::ValidatorPubkey { index: position });
        }
    }

    Ok(())
}

fn deser_pubkey_hex<'de, D>(d: D) -> Result<ValidatorPubkeyBytes, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let s = String::deserialize(d)?;
    let s = s.strip_prefix("0x").unwrap_or(&s);
    let bytes =
        hex::decode(s).map_err(|_| D::Error::custom(format!("pubkey is not valid hex: {s}")))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        D::Error::custom(format!("pubkey has length {} (expected 52)", v.len()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        primitives::HashTreeRoot as _,
        state::{State, Validator},
    };

    const ATT_PUBKEY_A: &str = "cd323f232b34ab26d6db7402c886e74ca81cfd3a0c659d2fe022356f25592f7d2d25ca7b19604f5a180037046cf2a02e1da4a800";
    const PROP_PUBKEY_A: &str = "b7b0f72e24801b02bda64073cb4de6699a416b37dfead227d7ca3922647c940fa03e4c012e8a0e656b731934aeac124a5337e333";
    const ATT_PUBKEY_B: &str = "8d9cbc508b20ef43e165f8559c1bdd18aaeda805ef565a4f9ffd6e4fbed01c05e143e305017847445859650d6dd06e6efb3f8410";
    const PROP_PUBKEY_B: &str = "cd323f232b34ab26d6db7402c886e74ca81cfd3a0c659d2fe022356f25592f7d2d25ca7b19604f5a180037046cf2a02e1da4a800";
    const ATT_PUBKEY_C: &str = "b7b0f72e24801b02bda64073cb4de6699a416b37dfead227d7ca3922647c940fa03e4c012e8a0e656b731934aeac124a5337e333";
    const PROP_PUBKEY_C: &str = "8d9cbc508b20ef43e165f8559c1bdd18aaeda805ef565a4f9ffd6e4fbed01c05e143e305017847445859650d6dd06e6efb3f8410";

    const TEST_CONFIG_YAML: &str = r#"# Genesis Settings
GENESIS_TIME: 1770407233

# Key Settings
ACTIVE_EPOCH: 18

# Validator Settings
VALIDATOR_COUNT: 3

# Genesis Validator Pubkeys
GENESIS_VALIDATORS:
    - attestation_pubkey: "cd323f232b34ab26d6db7402c886e74ca81cfd3a0c659d2fe022356f25592f7d2d25ca7b19604f5a180037046cf2a02e1da4a800"
      proposal_pubkey: "b7b0f72e24801b02bda64073cb4de6699a416b37dfead227d7ca3922647c940fa03e4c012e8a0e656b731934aeac124a5337e333"
    - attestation_pubkey: "8d9cbc508b20ef43e165f8559c1bdd18aaeda805ef565a4f9ffd6e4fbed01c05e143e305017847445859650d6dd06e6efb3f8410"
      proposal_pubkey: "cd323f232b34ab26d6db7402c886e74ca81cfd3a0c659d2fe022356f25592f7d2d25ca7b19604f5a180037046cf2a02e1da4a800"
    - attestation_pubkey: "b7b0f72e24801b02bda64073cb4de6699a416b37dfead227d7ca3922647c940fa03e4c012e8a0e656b731934aeac124a5337e333"
      proposal_pubkey: "8d9cbc508b20ef43e165f8559c1bdd18aaeda805ef565a4f9ffd6e4fbed01c05e143e305017847445859650d6dd06e6efb3f8410"
"#;

    #[test]
    fn deserialize_genesis_config() {
        let config: GenesisConfig = serde_yaml_ng::from_str(TEST_CONFIG_YAML)
            .expect("Failed to deserialize genesis config");

        assert_eq!(config.genesis_time, 1770407233);
        assert_eq!(config.genesis_validators.len(), 3);
        assert_eq!(
            config.genesis_validators[0].attestation_pubkey,
            hex::decode(ATT_PUBKEY_A).unwrap().as_slice()
        );
        assert_eq!(
            config.genesis_validators[0].proposal_pubkey,
            hex::decode(PROP_PUBKEY_A).unwrap().as_slice()
        );
        assert_eq!(
            config.genesis_validators[1].attestation_pubkey,
            hex::decode(ATT_PUBKEY_B).unwrap().as_slice()
        );
        assert_eq!(
            config.genesis_validators[1].proposal_pubkey,
            hex::decode(PROP_PUBKEY_B).unwrap().as_slice()
        );
        assert_eq!(
            config.genesis_validators[2].attestation_pubkey,
            hex::decode(ATT_PUBKEY_C).unwrap().as_slice()
        );
        assert_eq!(
            config.genesis_validators[2].proposal_pubkey,
            hex::decode(PROP_PUBKEY_C).unwrap().as_slice()
        );
    }

    #[test]
    fn state_from_genesis_uses_defaults() {
        let validators = vec![Validator {
            attestation_pubkey: hex::decode(ATT_PUBKEY_A).unwrap().try_into().unwrap(),
            proposal_pubkey: hex::decode(PROP_PUBKEY_A).unwrap().try_into().unwrap(),
            index: 0,
        }];

        let state = State::from_genesis(1770407233, validators);

        assert_eq!(state.config.genesis_time, 1770407233);
        assert_eq!(state.slot, 0);
        assert!(state.latest_justified.root.is_zero());
        assert_eq!(state.latest_justified.slot, 0);
        assert!(state.latest_finalized.root.is_zero());
        assert_eq!(state.latest_finalized.slot, 0);
        assert!(state.historical_block_hashes.is_empty());
        assert!(state.justified_slots.is_empty());
        assert!(state.justifications_roots.is_empty());
        assert!(state.justifications_validators.is_empty());
    }

    #[test]
    fn state_from_genesis_root() {
        let config: GenesisConfig = serde_yaml_ng::from_str(TEST_CONFIG_YAML).unwrap();
        let validators = config.validators();
        let state = State::from_genesis(config.genesis_time, validators);
        let root = state.hash_tree_root();

        // Pin the state root so SSZ layout changes are caught immediately.
        let expected_state_root = crate::primitives::H256::from_slice(
            &hex::decode("babcdc9235a29dfc0d605961df51cfc85732f85291c2beea8b7510a92ec458fe")
                .unwrap(),
        );
        assert_eq!(root, expected_state_root, "state root mismatch");

        let mut block = state.latest_block_header;
        block.state_root = root;
        let block_root = block.hash_tree_root();
        let expected_block_root = crate::primitives::H256::from_slice(
            &hex::decode("66a8beaa81d2aaeac7212d4bf8f5fea2bd22d479566a33a83c891661c21235ef")
                .unwrap(),
        );
        assert_eq!(block_root, expected_block_root, "block root mismatch");
    }

    fn test_config() -> GenesisConfig {
        serde_yaml_ng::from_str(TEST_CONFIG_YAML).unwrap()
    }

    /// State of a chain started from `config`, advanced past genesis so the
    /// check is exercised on something other than the anchor itself.
    fn state_of(config: &GenesisConfig) -> State {
        let mut state = State::from_genesis(config.genesis_time, config.validators());
        state.slot = 42;
        state
    }

    #[test]
    fn verify_state_accepts_state_from_same_genesis() {
        let config = test_config();
        assert_eq!(config.verify_state(&state_of(&config)), Ok(()));
    }

    #[test]
    fn verify_state_rejects_different_genesis_time() {
        let config = test_config();
        let mut other = test_config();
        other.genesis_time = config.genesis_time + 1;

        assert_eq!(
            config.verify_state(&state_of(&other)),
            Err(GenesisMismatch::GenesisTime {
                expected: config.genesis_time,
                got: config.genesis_time + 1,
            })
        );
    }

    #[test]
    fn verify_state_rejects_different_validator_count() {
        let config = test_config();
        let mut other = test_config();
        other.genesis_validators.pop();

        assert_eq!(
            config.verify_state(&state_of(&other)),
            Err(GenesisMismatch::ValidatorCount {
                expected: 3,
                got: 2,
            })
        );
    }

    /// Same validator count and same genesis time, different keys: the case a
    /// genesis-time-only check cannot see.
    #[test]
    fn verify_state_rejects_different_validator_keys() {
        let config = test_config();
        let mut other = test_config();
        other.genesis_validators.swap(0, 1);

        assert_eq!(
            config.verify_state(&state_of(&other)),
            Err(GenesisMismatch::ValidatorPubkey { index: 0 })
        );
    }

    #[test]
    fn verify_state_rejects_non_sequential_validator_indices() {
        let config = test_config();
        let mut validators = config.validators();
        validators[1].index = 7;
        let state = State::from_genesis(config.genesis_time, validators);

        assert_eq!(
            config.verify_state(&state),
            Err(GenesisMismatch::NonSequentialIndex {
                position: 1,
                got: 7,
            })
        );
    }
}
