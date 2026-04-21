use serde::Deserialize;

use crate::state::{Validator, ValidatorPubkeyBytes};

/// A single validator entry in the genesis config with dual public keys.
///
/// Deserializes from either shape:
///
/// - A map with `attestation_pubkey` and `proposal_pubkey` (the canonical,
///   production-style layout with independent signing keys per role).
/// - A plain hex string (the lean-quickstart / single-key devnet layout),
///   in which case the same pubkey is used for both roles. This matches how
///   zeam and lantern already interpret that field.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "GenesisValidatorEntryRaw")]
pub struct GenesisValidatorEntry {
    pub attestation_pubkey: ValidatorPubkeyBytes,
    pub proposal_pubkey: ValidatorPubkeyBytes,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum GenesisValidatorEntryRaw {
    Flat(String),
    Dual {
        attestation_pubkey: String,
        proposal_pubkey: String,
    },
}

impl TryFrom<GenesisValidatorEntryRaw> for GenesisValidatorEntry {
    type Error = String;

    fn try_from(raw: GenesisValidatorEntryRaw) -> Result<Self, Self::Error> {
        match raw {
            GenesisValidatorEntryRaw::Flat(pubkey) => {
                let bytes = parse_pubkey_hex(&pubkey)?;
                Ok(Self {
                    attestation_pubkey: bytes,
                    proposal_pubkey: bytes,
                })
            }
            GenesisValidatorEntryRaw::Dual {
                attestation_pubkey,
                proposal_pubkey,
            } => Ok(Self {
                attestation_pubkey: parse_pubkey_hex(&attestation_pubkey)?,
                proposal_pubkey: parse_pubkey_hex(&proposal_pubkey)?,
            }),
        }
    }
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
}

fn parse_pubkey_hex(s: &str) -> Result<ValidatorPubkeyBytes, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|_| format!("pubkey is not valid hex: {s}"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("pubkey has length {} (expected 52)", v.len()))
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
    fn deserialize_genesis_config_flat_pubkeys() {
        // lean-quickstart / single-key devnet layout: one pubkey per validator,
        // used for both attestation and proposal roles.
        let yaml = format!(
            r#"GENESIS_TIME: 1770407233
GENESIS_VALIDATORS:
    - "{ATT_PUBKEY_A}"
    - "0x{ATT_PUBKEY_B}"
"#
        );

        let config: GenesisConfig =
            serde_yaml_ng::from_str(&yaml).expect("Failed to deserialize flat-key genesis config");

        assert_eq!(config.genesis_validators.len(), 2);
        assert_eq!(
            config.genesis_validators[0].attestation_pubkey,
            config.genesis_validators[0].proposal_pubkey,
            "flat pubkey must be shared across both roles"
        );
        assert_eq!(
            config.genesis_validators[0].attestation_pubkey,
            hex::decode(ATT_PUBKEY_A).unwrap().as_slice()
        );
        assert_eq!(
            config.genesis_validators[1].attestation_pubkey,
            hex::decode(ATT_PUBKEY_B).unwrap().as_slice()
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
}
