//! Fork-aware decode of every subscribed gossip topic.
//!
//! SSZ carries no type tag, so the fork has to come from context. For three
//! topics the context is inside the payload: the slot sits at a position fixed
//! by the container's layout, and slot maps to epoch maps to [`ForkName`]. The
//! other four topics carry containers whose shape has not changed since the
//! fork that introduced them, so they decode with no fork lookup at all.
//! `data_column_sidecar_{subnet_id}`, the one family among the subscribed
//! topics rather than a fixed name, decodes with no lookup either, for a
//! different reason: fulu is the only fork that defines the container, so
//! there is no ladder to begin with (see [`decode_data_column_sidecar`]).
//!
//! | Topic | Fork-dependent |
//! |---|---|
//! | `beacon_block` | Yes, every fork |
//! | `beacon_aggregate_and_proof` | Yes, at electra |
//! | `attester_slashing` | Yes, at electra |
//! | `voluntary_exit`, `proposer_slashing` | No |
//! | `bls_to_execution_change` | No, capella onward |
//! | `sync_committee_contribution_and_proof` | No, altair onward |
//! | `data_column_sidecar_{subnet_id}` | No, fulu only |

use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::containers::{
    SignedBeaconBlock, altair, capella, electra, fulu, phase0, shared,
};
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::preset;
use ethlambda_types::beacon::primitives::Slot;
use libssz::SszDecode as _;

use super::topics;

/// An aggregate attestation with its selection proof, in whichever shape the
/// slot's fork gives it. Electra widened `Attestation` with `committee_bits`.
#[derive(Debug, Clone, PartialEq)]
pub enum SignedAggregateAndProof {
    Phase0(phase0::SignedAggregateAndProof),
    Electra(electra::SignedAggregateAndProof),
}

impl SignedAggregateAndProof {
    /// The validator that was selected to aggregate this committee's votes.
    pub fn aggregator_index(&self) -> u64 {
        match self {
            Self::Phase0(signed) => signed.message.aggregator_index,
            Self::Electra(signed) => signed.message.aggregator_index,
        }
    }

    /// The slot the aggregated attestation votes at.
    pub fn slot(&self) -> Slot {
        match self {
            Self::Phase0(signed) => signed.message.aggregate.data.slot,
            Self::Electra(signed) => signed.message.aggregate.data.slot,
        }
    }

    /// The epoch and root the aggregate's `target` checkpoint names.
    pub fn target(&self) -> (u64, ethlambda_types::beacon::primitives::Root) {
        let target = match self {
            Self::Phase0(signed) => &signed.message.aggregate.data.target,
            Self::Electra(signed) => &signed.message.aggregate.data.target,
        };
        (target.epoch, target.root)
    }

    /// How many attesters the aggregate covers.
    ///
    /// Counts set bits rather than reporting the bitfield's length: from
    /// electra on, `aggregation_bits` spans every committee named in
    /// `committee_bits`, so its length says how wide the aggregate could be,
    /// not how many validators actually signed.
    pub fn attester_count(&self) -> usize {
        match self {
            Self::Phase0(signed) => signed.message.aggregate.aggregation_bits.count_ones(),
            Self::Electra(signed) => signed.message.aggregate.aggregation_bits.count_ones(),
        }
    }
}

/// Slashing evidence, in whichever shape the slot's fork gives it. Electra
/// widened `IndexedAttestation`'s committee bound.
#[derive(Debug, Clone, PartialEq)]
pub enum AttesterSlashing {
    Phase0(phase0::AttesterSlashing),
    Electra(electra::AttesterSlashing),
}

/// A decoded gossip payload, one variant per subscribed topic.
#[derive(Debug, Clone, PartialEq)]
pub enum BeaconGossip {
    Block(Box<SignedBeaconBlock>),
    AggregateAndProof(Box<SignedAggregateAndProof>),
    AttesterSlashing(Box<AttesterSlashing>),
    VoluntaryExit(shared::SignedVoluntaryExit),
    /// Boxed for the same reason the fork-dependent variants are: two signed
    /// block headers make this the widest payload of the seven, and an unboxed
    /// one sets the size of every `BeaconGossip` the handler moves.
    ProposerSlashing(Box<shared::ProposerSlashing>),
    BlsToExecutionChange(capella::SignedBLSToExecutionChange),
    SyncCommitteeContribution(Box<altair::SignedContributionAndProof>),
}

impl BeaconGossip {
    /// The topic kind this payload came from, for logs and metrics.
    pub fn topic_kind(&self) -> &'static str {
        match self {
            BeaconGossip::Block(_) => topics::BEACON_BLOCK,
            BeaconGossip::AggregateAndProof(_) => topics::BEACON_AGGREGATE_AND_PROOF,
            BeaconGossip::AttesterSlashing(_) => topics::ATTESTER_SLASHING,
            BeaconGossip::VoluntaryExit(_) => topics::VOLUNTARY_EXIT,
            BeaconGossip::ProposerSlashing(_) => topics::PROPOSER_SLASHING,
            BeaconGossip::BlsToExecutionChange(_) => topics::BLS_TO_EXECUTION_CHANGE,
            BeaconGossip::SyncCommitteeContribution(_) => {
                topics::SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// A topic this node never subscribed to.
    UnknownTopic,
    /// The payload is shorter than the offsets it claims to carry.
    Truncated,
    /// SSZ rejected the payload for the fork the slot selected.
    Ssz,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownTopic => write!(f, "unsubscribed topic"),
            Self::Truncated => write!(f, "payload truncated before the slot"),
            Self::Ssz => write!(f, "ssz decode failed"),
        }
    }
}

/// The four-byte little-endian SSZ offset at `at`.
fn read_offset(bytes: &[u8], at: usize) -> Result<usize, DecodeError> {
    let raw: [u8; 4] = bytes
        .get(at..at + 4)
        .ok_or(DecodeError::Truncated)?
        .try_into()
        .expect("the slice is exactly four bytes");
    Ok(u32::from_le_bytes(raw) as usize)
}

/// The eight-byte little-endian `uint64` at `at`.
fn read_u64(bytes: &[u8], at: usize) -> Result<u64, DecodeError> {
    let raw: [u8; 8] = bytes
        .get(at..at + 8)
        .ok_or(DecodeError::Truncated)?
        .try_into()
        .expect("the slice is exactly eight bytes");
    Ok(u64::from_le_bytes(raw))
}

/// The `slot` of a `SignedBeaconBlock`.
///
/// The container's fixed part is the offset to `message` followed by
/// `signature`, so the first variable element starts at the offset the first
/// four bytes carry, and `BeaconBlock`'s own first field is `slot`. Reading the
/// offset rather than assuming its value keeps this correct even if a future
/// fork adds a fixed field ahead of `message`.
pub fn block_slot(bytes: &[u8]) -> Result<Slot, DecodeError> {
    read_u64(bytes, read_offset(bytes, 0)?)
}

/// The `slot` of a `SignedAggregateAndProof`.
///
/// `message` is the first variable element of the outer container.
/// `AggregateAndProof`'s fixed part is `aggregator_index`, then the offset to
/// `aggregate`, then `selection_proof`, so the aggregate's offset sits eight
/// bytes into the message. `Attestation`'s fixed part opens with the offset to
/// `aggregation_bits` and is followed immediately by `data`, whose first field
/// is `slot`, at every fork.
pub fn aggregate_slot(bytes: &[u8]) -> Result<Slot, DecodeError> {
    let message = read_offset(bytes, 0)?;
    let aggregate = message
        .checked_add(read_offset(
            bytes,
            message.checked_add(8).ok_or(DecodeError::Truncated)?,
        )?)
        .ok_or(DecodeError::Truncated)?;
    read_u64(
        bytes,
        aggregate.checked_add(4).ok_or(DecodeError::Truncated)?,
    )
}

/// The `slot` of an `AttesterSlashing`, taken from its first attestation.
///
/// The container is two offsets. `IndexedAttestation`'s fixed part opens with
/// the offset to `attesting_indices` and is followed immediately by `data`.
pub fn attester_slashing_slot(bytes: &[u8]) -> Result<Slot, DecodeError> {
    let attestation_1 = read_offset(bytes, 0)?;
    read_u64(
        bytes,
        attestation_1.checked_add(4).ok_or(DecodeError::Truncated)?,
    )
}

/// The fork whose rules apply to `slot`.
pub fn fork_at_slot(config: &Config, slot: Slot) -> ForkName {
    config.fork_at_epoch(slot / preset::SLOTS_PER_EPOCH)
}

/// Decode a `beacon_block` payload, at the fork its own slot names.
///
/// Separate from [`decode_gossip`] because the two topics worth logging in
/// detail are dispatched by name, and a handler that already knows it is
/// holding a block should not have to unwrap a [`BeaconGossip`] to find one.
pub fn decode_block(config: &Config, bytes: &[u8]) -> Result<SignedBeaconBlock, DecodeError> {
    let fork = fork_at_slot(config, block_slot(bytes)?);
    SignedBeaconBlock::from_ssz(fork, bytes).map_err(|_| DecodeError::Ssz)
}

/// Decode a data column sidecar off a subnet topic.
///
/// Takes no `Config` and no fork, unlike [`decode_block`]: only fulu defines
/// this container, so there is no fork ladder to choose from. A sidecar whose
/// slot predates fulu is rejected later, by the checks that know the schedule.
pub fn decode_data_column_sidecar(bytes: &[u8]) -> Result<fulu::DataColumnSidecar, DecodeError> {
    fulu::DataColumnSidecar::from_ssz_bytes(bytes).map_err(|_| DecodeError::Ssz)
}

/// Decode a `beacon_aggregate_and_proof` payload, at the fork its slot names.
pub fn decode_aggregate_and_proof(
    config: &Config,
    bytes: &[u8],
) -> Result<SignedAggregateAndProof, DecodeError> {
    let fork = fork_at_slot(config, aggregate_slot(bytes)?);
    if fork >= ForkName::Electra {
        electra::SignedAggregateAndProof::from_ssz_bytes(bytes)
            .map(SignedAggregateAndProof::Electra)
    } else {
        phase0::SignedAggregateAndProof::from_ssz_bytes(bytes).map(SignedAggregateAndProof::Phase0)
    }
    .map_err(|_| DecodeError::Ssz)
}

/// Decode a decompressed gossip payload according to its topic kind.
///
/// The caller has already snappy-decompressed and already matched the topic
/// against the subscribed set, so an `UnknownTopic` here means the gossipsub
/// subscription set and this function have drifted apart.
pub fn decode_gossip(
    config: &Config,
    topic_kind: &str,
    bytes: &[u8],
) -> Result<BeaconGossip, DecodeError> {
    match topic_kind {
        topics::BEACON_BLOCK => {
            decode_block(config, bytes).map(|block| BeaconGossip::Block(Box::new(block)))
        }
        topics::BEACON_AGGREGATE_AND_PROOF => decode_aggregate_and_proof(config, bytes)
            .map(|value| BeaconGossip::AggregateAndProof(Box::new(value))),
        topics::ATTESTER_SLASHING => {
            let fork = fork_at_slot(config, attester_slashing_slot(bytes)?);
            let decoded = if fork >= ForkName::Electra {
                electra::AttesterSlashing::from_ssz_bytes(bytes).map(AttesterSlashing::Electra)
            } else {
                phase0::AttesterSlashing::from_ssz_bytes(bytes).map(AttesterSlashing::Phase0)
            };
            decoded
                .map(|value| BeaconGossip::AttesterSlashing(Box::new(value)))
                .map_err(|_| DecodeError::Ssz)
        }
        topics::VOLUNTARY_EXIT => shared::SignedVoluntaryExit::from_ssz_bytes(bytes)
            .map(BeaconGossip::VoluntaryExit)
            .map_err(|_| DecodeError::Ssz),
        topics::PROPOSER_SLASHING => shared::ProposerSlashing::from_ssz_bytes(bytes)
            .map(|value| BeaconGossip::ProposerSlashing(Box::new(value)))
            .map_err(|_| DecodeError::Ssz),
        topics::BLS_TO_EXECUTION_CHANGE => {
            capella::SignedBLSToExecutionChange::from_ssz_bytes(bytes)
                .map(BeaconGossip::BlsToExecutionChange)
                .map_err(|_| DecodeError::Ssz)
        }
        topics::SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF => {
            altair::SignedContributionAndProof::from_ssz_bytes(bytes)
                .map(|value| BeaconGossip::SyncCommitteeContribution(Box::new(value)))
                .map_err(|_| DecodeError::Ssz)
        }
        _ => Err(DecodeError::UnknownTopic),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethlambda_types::beacon::primitives::{BlsSignature, Bytes32, Root};
    use libssz::SszEncode as _;

    /// The first slot of `epoch`.
    fn slot_of(epoch: u64) -> Slot {
        epoch * preset::SLOTS_PER_EPOCH
    }

    fn phase0_block(slot: Slot) -> phase0::SignedBeaconBlock {
        phase0::SignedBeaconBlock {
            message: phase0::BeaconBlock {
                slot,
                proposer_index: 7,
                parent_root: Root::repeat_byte(1),
                state_root: Root::repeat_byte(2),
                body: phase0::BeaconBlockBody {
                    randao_reveal: BlsSignature::default(),
                    eth1_data: shared::Eth1Data::default(),
                    graffiti: Bytes32::ZERO,
                    proposer_slashings: Default::default(),
                    attester_slashings: Default::default(),
                    attestations: Default::default(),
                    deposits: Default::default(),
                    voluntary_exits: Default::default(),
                },
            },
            signature: BlsSignature::default(),
        }
    }

    #[test]
    fn the_preset_is_mainnet() {
        // Every epoch computed here divides by this. If `preset-minimal` ever
        // leaks into ethlambda-p2p's feature resolution, the beacon wire would
        // silently compute epochs eight slots wide and pick the wrong fork.
        assert_eq!(preset::SLOTS_PER_EPOCH, 32);
    }

    #[test]
    fn block_slot_is_read_from_the_encoding() {
        let slot = slot_of(1_000);
        let bytes = phase0_block(slot).to_ssz();
        assert_eq!(block_slot(&bytes), Ok(slot));
    }

    #[test]
    fn fork_selection_follows_the_mainnet_schedule() {
        let config = Config::mainnet();
        let boundaries = [
            (0u64, ForkName::Phase0),
            (74_240, ForkName::Altair),
            (144_896, ForkName::Bellatrix),
            (194_048, ForkName::Capella),
            (269_568, ForkName::Deneb),
            (364_032, ForkName::Electra),
            (411_392, ForkName::Fulu),
        ];
        for (epoch, fork) in boundaries {
            assert_eq!(fork_at_slot(&config, slot_of(epoch)), fork, "epoch {epoch}");
            if epoch > 0 {
                assert_ne!(
                    fork_at_slot(&config, slot_of(epoch) - 1),
                    fork,
                    "the slot before epoch {epoch} must still be the previous fork"
                );
            }
        }
    }

    #[test]
    fn a_phase0_block_round_trips_through_decode_gossip() {
        let config = Config::mainnet();
        let block = phase0_block(slot_of(10));
        let decoded =
            decode_gossip(&config, topics::BEACON_BLOCK, &block.to_ssz()).expect("decodes");
        assert_eq!(
            decoded,
            BeaconGossip::Block(Box::new(SignedBeaconBlock::Phase0(block)))
        );
        assert_eq!(decoded.topic_kind(), topics::BEACON_BLOCK);
    }

    #[test]
    fn the_slot_actually_drives_which_shape_is_decoded() {
        // A phase0-shaped payload whose slot lands in fulu must be refused, not
        // decoded as phase0. Without this, `decode_gossip` could ignore the
        // slot entirely and every test above would still pass.
        let config = Config::mainnet();
        let bytes = phase0_block(slot_of(config.fulu_fork_epoch)).to_ssz();
        assert_eq!(
            decode_gossip(&config, topics::BEACON_BLOCK, &bytes),
            Err(DecodeError::Ssz)
        );
    }

    #[test]
    fn a_voluntary_exit_needs_no_fork_lookup() {
        let config = Config::mainnet();
        let exit = shared::SignedVoluntaryExit::default();
        let decoded =
            decode_gossip(&config, topics::VOLUNTARY_EXIT, &exit.to_ssz()).expect("decodes");
        assert_eq!(decoded, BeaconGossip::VoluntaryExit(exit));
    }

    #[test]
    fn a_proposer_slashing_needs_no_fork_lookup() {
        let config = Config::mainnet();
        let slashing = shared::ProposerSlashing::default();
        let decoded =
            decode_gossip(&config, topics::PROPOSER_SLASHING, &slashing.to_ssz()).expect("decodes");
        assert_eq!(decoded, BeaconGossip::ProposerSlashing(Box::new(slashing)));
    }

    #[test]
    fn a_sidecar_decodes_and_a_truncated_one_does_not() {
        let sidecar = fulu::DataColumnSidecar {
            index: 3,
            column: Default::default(),
            kzg_commitments: Default::default(),
            kzg_proofs: Default::default(),
            signed_block_header: Default::default(),
            // `SszVector` has no blanket `Default`, unlike the `SszList`
            // fields above: a vector's whole point is a length fixed at the
            // type level, so there is no length-zero default to fall back on.
            kzg_commitments_inclusion_proof: vec![
                Root::default();
                preset::KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH
            ]
            .try_into()
            .expect("exactly the required depth"),
        };
        let bytes = sidecar.to_ssz();
        assert_eq!(decode_data_column_sidecar(&bytes).unwrap().index, 3);
        assert!(decode_data_column_sidecar(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn an_unsubscribed_topic_is_refused() {
        let config = Config::mainnet();
        assert_eq!(
            decode_gossip(&config, "beacon_attestation_3", &[0u8; 8]),
            Err(DecodeError::UnknownTopic)
        );
    }

    #[test]
    fn a_truncated_payload_is_refused_rather_than_panicking() {
        // Every slot read indexes into attacker-supplied bytes, so this is the
        // property that stops a two-byte gossip message from taking the node
        // down.
        let config = Config::mainnet();
        for length in 0..16 {
            let bytes = vec![0xffu8; length];
            for kind in topics::SUBSCRIBED_TOPIC_KINDS {
                let result = decode_gossip(&config, kind, &bytes);
                assert!(result.is_err(), "{kind} accepted {length} junk bytes");
            }
        }
    }
}
