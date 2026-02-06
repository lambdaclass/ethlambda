use serde::Deserialize;

use crate::state::ValidatorPubkeyBytes;

#[derive(Debug, Clone, Deserialize)]
pub struct GenesisConfig {
    #[serde(rename = "GENESIS_TIME")]
    pub genesis_time: u64,
    #[serde(rename = "GENESIS_VALIDATORS")]
    #[serde(deserialize_with = "deser_hex_pubkeys")]
    pub genesis_validators: Vec<ValidatorPubkeyBytes>,
}

fn deser_hex_pubkeys<'de, D>(d: D) -> Result<Vec<ValidatorPubkeyBytes>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let hex_strings: Vec<String> = Vec::deserialize(d)?;
    hex_strings
        .into_iter()
        .map(|s| {
            let s = s.strip_prefix("0x").unwrap_or(&s);
            let bytes = hex::decode(s)
                .map_err(|_| D::Error::custom("GENESIS_VALIDATORS value is not valid hex"))?;
            bytes
                .try_into()
                .map_err(|_| D::Error::custom("GENESIS_VALIDATORS pubkey length != 52"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        primitives::ssz::TreeHash,
        state::{State, Validator},
    };

    const PUBKEY_A: &str = "cd323f232b34ab26d6db7402c886e74ca81cfd3a0c659d2fe022356f25592f7d2d25ca7b19604f5a180037046cf2a02e1da4a800";
    const PUBKEY_B: &str = "b7b0f72e24801b02bda64073cb4de6699a416b37dfead227d7ca3922647c940fa03e4c012e8a0e656b731934aeac124a5337e333";
    const PUBKEY_C: &str = "8d9cbc508b20ef43e165f8559c1bdd18aaeda805ef565a4f9ffd6e4fbed01c05e143e305017847445859650d6dd06e6efb3f8410";

    const TEST_CONFIG_JSON: &str = r#"# Genesis Settings
GENESIS_TIME: 1770407233

# Key Settings
ACTIVE_EPOCH: 18

# Validator Settings  
VALIDATOR_COUNT: 3

# Genesis Validator Pubkeys
GENESIS_VALIDATORS:
    - "cd323f232b34ab26d6db7402c886e74ca81cfd3a0c659d2fe022356f25592f7d2d25ca7b19604f5a180037046cf2a02e1da4a800"
    - "b7b0f72e24801b02bda64073cb4de6699a416b37dfead227d7ca3922647c940fa03e4c012e8a0e656b731934aeac124a5337e333"
    - "8d9cbc508b20ef43e165f8559c1bdd18aaeda805ef565a4f9ffd6e4fbed01c05e143e305017847445859650d6dd06e6efb3f8410"
"#;

    #[test]
    fn deserialize_genesis_config() {
        let config: GenesisConfig = serde_yaml_ng::from_str(TEST_CONFIG_JSON)
            .expect("Failed to deserialize genesis config");

        assert_eq!(config.genesis_time, 1770407233);
        assert_eq!(config.genesis_validators.len(), 3);
        assert_eq!(
            config.genesis_validators[0],
            hex::decode(PUBKEY_A).unwrap().as_slice()
        );
        assert_eq!(
            config.genesis_validators[1],
            hex::decode(PUBKEY_B).unwrap().as_slice()
        );
        assert_eq!(
            config.genesis_validators[2],
            hex::decode(PUBKEY_C).unwrap().as_slice()
        );
    }

    #[test]
    fn state_from_genesis_uses_defaults() {
        let validators = vec![Validator {
            pubkey: hex::decode(PUBKEY_A).unwrap().try_into().unwrap(),
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
        let config: GenesisConfig = serde_yaml_ng::from_str(TEST_CONFIG_JSON).unwrap();

        let validators: Vec<Validator> = config
            .genesis_validators
            .into_iter()
            .enumerate()
            .map(|(i, pubkey)| Validator {
                pubkey,
                index: i as u64,
            })
            .collect();
        let state = State::from_genesis(config.genesis_time, validators);
        let root = state.tree_hash_root();

        // Pin the state root so changes are caught immediately.
        let expected =
            hex::decode("362db4ffe968f1d100934797f6d3c7985b4aee9d96b328ad2e47243b8292e434")
                .unwrap();
        assert_eq!(root.as_slice(), &expected[..], "state root mismatch");

        let expected_block_root =
            hex::decode("8b04a5a7c03abda086237c329392953a0308888e4a22481a39ce06a95f38b8c4")
                .unwrap();
        let mut block = state.latest_block_header;
        block.state_root = root;
        let block_root = block.tree_hash_root();
        assert_eq!(
            block_root.as_slice(),
            &expected_block_root[..],
            "justified root mismatch"
        );
    }
}
