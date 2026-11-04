//! The four operations a block carries besides attestations, as one value for
//! the code that moves them between gossip, the Beacon API and the pool.

use libssz::SszEncode as _;

use super::containers::{capella, electra, shared};

/// One proposer slashing, attester slashing, voluntary exit or BLS change, in
/// the shapes fulu's gossip topics carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeaconOperation {
    ProposerSlashing(shared::ProposerSlashing),
    AttesterSlashing(electra::AttesterSlashing),
    VoluntaryExit(shared::SignedVoluntaryExit),
    BlsToExecutionChange(capella::SignedBLSToExecutionChange),
}

impl BeaconOperation {
    /// The SSZ encoding gossip publishes.
    pub fn to_ssz(&self) -> Vec<u8> {
        match self {
            Self::ProposerSlashing(op) => op.to_ssz(),
            Self::AttesterSlashing(op) => op.to_ssz(),
            Self::VoluntaryExit(op) => op.to_ssz(),
            Self::BlsToExecutionChange(op) => op.to_ssz(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::primitives::{BlsPubkey, BlsSignature, H160};

    fn round_trip<T>(op: &T)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let json = serde_json::to_value(op).unwrap();
        assert_eq!(&serde_json::from_value::<T>(json).unwrap(), op);
    }

    #[test]
    fn serde_the_four_signed_operations_round_trip() {
        let header = shared::SignedBeaconBlockHeader {
            message: shared::BeaconBlockHeader {
                slot: 9,
                proposer_index: 4,
                ..Default::default()
            },
            signature: BlsSignature([1; 96]),
        };
        round_trip(&shared::ProposerSlashing {
            signed_header_1: header.clone(),
            signed_header_2: header,
        });
        round_trip(&shared::SignedVoluntaryExit {
            message: shared::VoluntaryExit {
                epoch: 3,
                validator_index: 8,
            },
            signature: BlsSignature([2; 96]),
        });
        round_trip(&capella::SignedBLSToExecutionChange {
            message: capella::BLSToExecutionChange {
                validator_index: 5,
                from_bls_pubkey: BlsPubkey([3; 48]),
                to_execution_address: H160([4; 20]),
            },
            signature: BlsSignature([5; 96]),
        });
        let indexed = |indices: Vec<u64>| electra::IndexedAttestation {
            attesting_indices: indices.try_into().unwrap(),
            data: Default::default(),
            signature: BlsSignature([6; 96]),
        };
        round_trip(&electra::AttesterSlashing {
            attestation_1: indexed(vec![1, 5, 9]),
            attestation_2: indexed(vec![5, 9, 12]),
        });
    }

    #[test]
    fn serde_a_beacon_api_voluntary_exit_decodes() {
        let json = serde_json::json!({
            "message": { "epoch": "1", "validator_index": "2" },
            "signature": format!("0x{}", "ab".repeat(96)),
        });
        let exit: shared::SignedVoluntaryExit = serde_json::from_value(json).unwrap();
        assert_eq!(exit.message.epoch, 1);
        assert_eq!(exit.message.validator_index, 2);
        assert_eq!(exit.signature, BlsSignature([0xab; 96]));
    }

    #[test]
    fn to_ssz_matches_the_wrapped_container() {
        let exit = shared::SignedVoluntaryExit::default();
        let expected = exit.to_ssz();
        assert_eq!(BeaconOperation::VoluntaryExit(exit).to_ssz(), expected);
    }
}
