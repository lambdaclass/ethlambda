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
//! `beacon_attestation_{subnet_id}` is the exception to reading the fork off
//! the payload: electra moved its slot, so its fork comes from the topic's
//! digest instead (see [`decode_attestation`]).
//!
//! | Topic | Fork-dependent |
//! |---|---|
//! | `beacon_block` | Yes, every fork |
//! | `beacon_aggregate_and_proof` | Yes, at electra |
//! | `attester_slashing` | Yes, at electra |
//! | `beacon_attestation_{subnet_id}` | Yes, at electra, by topic digest |
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
use ethlambda_types::time::unix_now_ms;
use libssz::SszDecode as _;

use super::topics;

/// An aggregate attestation with its selection proof, in whichever shape the
/// slot's fork gives it.
///
/// Re-exported rather than declared here, where it used to live. The gossip
/// path no longer ends at this decode: an aggregate now travels over
/// `ethlambda-network-api` to the chain actor and into fork choice, so the type
/// has to sit where every one of those layers can name it. The accessors this
/// module's own logging uses came with it.
pub use ethlambda_types::beacon::containers::SignedAggregateAndProof;

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
    /// The message's own fork (gloas, today) has no container modeled here
    /// yet. Distinct from [`Self::Ssz`] on purpose: an honest peer on a fork
    /// this build cannot decode is not sending malformed bytes, so a caller
    /// mapping this to a gossipsub verdict must not score it as `Reject` the
    /// way [`Self::Ssz`] is; see `gossipsub::handler`'s callers.
    UnsupportedFork,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownTopic => write!(f, "unsubscribed topic"),
            Self::Truncated => write!(f, "payload truncated before the slot"),
            Self::Ssz => write!(f, "ssz decode failed"),
            Self::UnsupportedFork => write!(f, "message's fork has no container modeled yet"),
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

/// The fork this node's own wall clock says is active right now.
///
/// [`decode_data_column_sidecar`] has no slot to look a fork up by the way
/// [`fork_at_slot`] does: only fulu's container is modeled, so nothing reads
/// a slot out of the bytes first. A caller on the gossip path uses this to
/// approximate, once that decode has already failed, whether the failure is
/// this build's own gap rather than the sender's fault. An approximation
/// only, since gossip topic subscriptions are frozen at startup and this
/// reads the live clock instead of whatever fork the topic was actually
/// built for; see [`decode_data_column_sidecar`]'s own doc and its caller in
/// `gossipsub::handler::triage_data_column`.
pub fn current_fork(config: &Config) -> ForkName {
    let slot = unix_now_ms()
        .saturating_sub(config.genesis_time_ms())
        .checked_div(config.slot_duration_ms)
        .unwrap_or(0);
    fork_at_slot(config, slot)
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
///
/// Gloas redefines this container too (no header, a `slot` field of its own;
/// see `containers::gloas::DataColumnSidecar`'s doc), so a gloas sidecar
/// fails here indistinguishably from a malformed one: nothing about these
/// bytes alone says which fork sent them. [`current_fork`] is what lets a
/// caller on the gossip path (where a wrong verdict scores an honest peer)
/// approximate the two apart from the outside instead, once this call has
/// already failed; see [`current_fork`]'s own doc for why it is only an
/// approximation.
pub fn decode_data_column_sidecar(bytes: &[u8]) -> Result<fulu::DataColumnSidecar, DecodeError> {
    fulu::DataColumnSidecar::from_ssz_bytes(bytes).map_err(|_| DecodeError::Ssz)
}

/// Decode a `beacon_aggregate_and_proof` payload, at the fork its slot names.
pub fn decode_aggregate_and_proof(
    config: &Config,
    bytes: &[u8],
) -> Result<SignedAggregateAndProof, DecodeError> {
    let fork = fork_at_slot(config, aggregate_slot(bytes)?);
    match fork {
        ForkName::Electra | ForkName::Fulu => {
            electra::SignedAggregateAndProof::from_ssz_bytes(bytes)
                .map(SignedAggregateAndProof::Electra)
        }
        ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb => phase0::SignedAggregateAndProof::from_ssz_bytes(bytes)
            .map(SignedAggregateAndProof::Phase0),
        // Gloas's own `AggregateAndProof` has no modeled variant here yet
        // (its attestation is progressive-list-shaped, EIP-7549 continued),
        // so this is refused rather than mis-decoded as electra's.
        // `UnsupportedFork`, not `Ssz`: the sender did nothing wrong.
        ForkName::Gloas => return Err(DecodeError::UnsupportedFork),
        ForkName::Lean => {
            unreachable!("fork_at_slot never returns Lean: it is absent from ForkName::ALL")
        }
    }
    .map_err(|_| DecodeError::Ssz)
}

/// An unaggregated attestation, in whichever shape the topic's fork gives it.
///
/// Electra split this topic differently from [`SignedAggregateAndProof`]'s. An
/// aggregate kept its container and widened it, but a subnet vote changed
/// container altogether: once EIP-7549 made `aggregation_bits` span every
/// committee in the slot, a lone attester's bit no longer said which committee
/// it sat in, so [`electra::SingleAttestation`] names `committee_index` and
/// `attester_index` outright.
#[derive(Debug, Clone, PartialEq)]
pub enum Attestation {
    Phase0(phase0::Attestation),
    Electra(electra::SingleAttestation),
}

impl Attestation {
    /// The fork-invariant half of the attestation.
    pub fn data(&self) -> ethlambda_types::beacon::containers::AttestationData {
        match self {
            Self::Phase0(attestation) => attestation.data,
            Self::Electra(attestation) => attestation.data,
        }
    }
}

/// Decode a `beacon_attestation_{subnet_id}` payload, in the shape `fork`
/// gives it.
///
/// The one fork-dependent topic whose fork cannot come from its own slot: the
/// two shapes put `slot` at different offsets, four bytes in for phase0's
/// `Attestation` and sixteen for `SingleAttestation`, so choosing the offset is
/// the question the slot was supposed to answer. The topic answers it instead.
/// `p2p-interface.md` types each topic by the fork its digest names, and
/// lighthouse decodes this one on that digest too. `fork` is the fork the
/// subscribed digest was computed at.
pub fn decode_attestation(fork: ForkName, bytes: &[u8]) -> Result<Attestation, DecodeError> {
    match fork {
        ForkName::Electra | ForkName::Fulu => {
            electra::SingleAttestation::from_ssz_bytes(bytes).map(Attestation::Electra)
        }
        ForkName::Phase0
        | ForkName::Altair
        | ForkName::Bellatrix
        | ForkName::Capella
        | ForkName::Deneb => phase0::Attestation::from_ssz_bytes(bytes).map(Attestation::Phase0),
        // Gloas's `SingleAttestation` has the same bytes as electra's, but its
        // `data.index` carries the payload-availability signal instead of
        // being zero, so electra's gossip rules would reject an honest vote.
        // `UnsupportedFork`, not `Ssz`: the sender did nothing wrong.
        ForkName::Gloas => return Err(DecodeError::UnsupportedFork),
        ForkName::Lean => {
            unreachable!("a beacon topic's fork is never Lean: it is absent from ForkName::ALL")
        }
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
            let decoded = match fork {
                ForkName::Electra | ForkName::Fulu => {
                    electra::AttesterSlashing::from_ssz_bytes(bytes).map(AttesterSlashing::Electra)
                }
                ForkName::Phase0
                | ForkName::Altair
                | ForkName::Bellatrix
                | ForkName::Capella
                | ForkName::Deneb => {
                    phase0::AttesterSlashing::from_ssz_bytes(bytes).map(AttesterSlashing::Phase0)
                }
                // Gloas's own `AttesterSlashing` has no modeled variant here
                // yet; see `decode_aggregate_and_proof`'s matching arm.
                ForkName::Gloas => return Err(DecodeError::UnsupportedFork),
                ForkName::Lean => {
                    unreachable!("fork_at_slot never returns Lean: it is absent from ForkName::ALL")
                }
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

    /// One attester's vote at `slot`, in the shape electra puts on a subnet.
    fn single_attestation(slot: Slot) -> electra::SingleAttestation {
        electra::SingleAttestation {
            committee_index: 5,
            attester_index: 123_456,
            data: shared::AttestationData {
                slot,
                beacon_block_root: Root::repeat_byte(1),
                ..Default::default()
            },
            signature: BlsSignature::default(),
        }
    }

    /// One attester's vote at `slot`, in the shape phase0 puts on a subnet: a
    /// whole `Attestation` with a single bit set.
    fn phase0_attestation(slot: Slot) -> phase0::Attestation {
        let mut aggregation_bits = phase0::AggregationBits::with_length(8).unwrap();
        aggregation_bits.set(3, true).unwrap();
        phase0::Attestation {
            aggregation_bits,
            data: shared::AttestationData {
                slot,
                beacon_block_root: Root::repeat_byte(1),
                ..Default::default()
            },
            signature: BlsSignature::default(),
        }
    }

    #[test]
    fn a_subnet_attestation_from_electra_on_is_a_single_attestation() {
        let config = Config::mainnet();
        let single = single_attestation(slot_of(config.fulu_fork_epoch));
        let decoded = decode_attestation(ForkName::Fulu, &single.to_ssz()).expect("decodes");
        assert_eq!(decoded, Attestation::Electra(single));
    }

    #[test]
    fn a_subnet_attestation_before_electra_is_a_whole_attestation() {
        let attestation = phase0_attestation(slot_of(10));
        let decoded = decode_attestation(ForkName::Deneb, &attestation.to_ssz()).expect("decodes");
        assert_eq!(decoded, Attestation::Phase0(attestation));
    }

    #[test]
    fn the_topic_fork_rather_than_the_payload_picks_the_attestation_shape() {
        // Each shape offered under the other's fork is refused rather than
        // misread. Without this, `decode_attestation` could ignore `fork` and
        // the two tests above would still pass.
        let single = single_attestation(slot_of(10)).to_ssz();
        assert_eq!(
            decode_attestation(ForkName::Deneb, &single),
            Err(DecodeError::Ssz)
        );
        let phase0 = phase0_attestation(slot_of(10)).to_ssz();
        assert_eq!(
            decode_attestation(ForkName::Electra, &phase0),
            Err(DecodeError::Ssz)
        );
    }

    #[test]
    fn a_subnet_attestation_at_gloas_is_unsupported_rather_than_malformed() {
        // Gloas reads `data.index` as the payload-availability signal, so
        // decoding these bytes with electra's rules would reject honest
        // votes. The bytes are valid, so the refusal must not be `Ssz`.
        let single = single_attestation(slot_of(10)).to_ssz();
        assert_eq!(
            decode_attestation(ForkName::Gloas, &single),
            Err(DecodeError::UnsupportedFork)
        );
    }

    #[test]
    fn a_truncated_subnet_attestation_is_refused() {
        let bytes = single_attestation(slot_of(10)).to_ssz();
        for length in 0..bytes.len() {
            assert!(decode_attestation(ForkName::Fulu, &bytes[..length]).is_err());
        }
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
