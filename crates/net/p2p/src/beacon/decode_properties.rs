//! Property tests for the beacon gossip decoders (`decode.rs`): every payload
//! a peer publishes goes through one of them before any rule looks at it.
//!
//! SSZ gives every value exactly one encoding, so the oracle needs no model:
//! whatever a decoder accepts must encode back to the very bytes it read. A
//! decoder that accepts a second encoding of a value (a bitlist without its
//! delimiter, a boolean byte of 2, offsets that overlap or leave a gap) treats
//! as valid what every other client refuses, and the message ID, which hashes
//! the bytes, no longer names the value. And no input may panic.
//!
//! Inputs are the consensus-specs `ssz_static` cases of each gossip container
//! at every fork it exists at (valid by construction, every field filled),
//! with the slot moved inside that fork for the decoders that choose a fork by
//! slot, then edited by a few byte-level mutations. The fixtures are the
//! `make consensus-spec-tests` download, so these tests run behind the
//! `beacon-spec-tests` feature (`make test-beacon-mainnet`) and report as
//! ignored without it. See `docs/property_testing.md`.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use ephyra::gens;
use ethlambda_types::beacon::config::Config;
use ethlambda_types::beacon::fork::ForkName;
use ethlambda_types::beacon::preset;
use libssz::SszEncode as _;

use super::decode::{self, AttesterSlashing, BeaconGossip, DecodeError, SignedAggregateAndProof};
use super::topics;

/// The schedule the properties decode under: mainnet's, with gloas one epoch
/// after fulu so that every fork, gloas included, has slots.
fn config() -> Config {
    let mut config = Config::mainnet();
    config.gloas_fork_epoch = config.fulu_fork_epoch + 1;
    config
}

/// Decodes `bytes` the way the gossip path does for one topic and encodes the
/// result again.
type RoundTrip = fn(&Config, ForkName, &[u8]) -> Result<Vec<u8>, DecodeError>;

/// Where a slot-dispatched decoder reads the slot, for moving a seed's slot
/// inside its own fork.
type SlotAt = fn(&[u8]) -> Option<usize>;

/// One gossip decoder and the fixture container its topic carries.
struct Target {
    topic: &'static str,
    /// The container's directory name under `ssz_static`, per fork range.
    containers: &'static [(&'static str, &'static [ForkName])],
    round_trip: RoundTrip,
    slot_at: Option<SlotAt>,
}

const PRE_ELECTRA: &[ForkName] = &[
    ForkName::Phase0,
    ForkName::Altair,
    ForkName::Bellatrix,
    ForkName::Capella,
    ForkName::Deneb,
];
const ELECTRA_ON: &[ForkName] = &[ForkName::Electra, ForkName::Fulu, ForkName::Gloas];
const ALTAIR_ON: &[ForkName] = &[
    ForkName::Altair,
    ForkName::Bellatrix,
    ForkName::Capella,
    ForkName::Deneb,
    ForkName::Electra,
    ForkName::Fulu,
    ForkName::Gloas,
];
const CAPELLA_ON: &[ForkName] = &[
    ForkName::Capella,
    ForkName::Deneb,
    ForkName::Electra,
    ForkName::Fulu,
    ForkName::Gloas,
];
const GLOAS: &[ForkName] = &[ForkName::Gloas];

fn u32_at(bytes: &[u8], at: usize) -> Option<usize> {
    let raw = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(raw.try_into().ok()?) as usize)
}

fn gossip(config: &Config, topic: &str, bytes: &[u8]) -> Result<Vec<u8>, DecodeError> {
    decode::decode_gossip(config, topic, bytes).map(|decoded| match decoded {
        BeaconGossip::Block(block) => block.to_ssz(),
        BeaconGossip::AggregateAndProof(aggregate) => aggregate_bytes(&aggregate),
        BeaconGossip::AttesterSlashing(slashing) => match *slashing {
            AttesterSlashing::Phase0(value) => value.to_ssz(),
            AttesterSlashing::Electra(value) => value.to_ssz(),
            AttesterSlashing::Gloas(value) => value.to_ssz(),
        },
        BeaconGossip::VoluntaryExit(value) => value.to_ssz(),
        BeaconGossip::ProposerSlashing(value) => value.to_ssz(),
        BeaconGossip::BlsToExecutionChange(value) => value.to_ssz(),
        BeaconGossip::SyncCommitteeContribution(value) => value.to_ssz(),
    })
}

fn aggregate_bytes(aggregate: &SignedAggregateAndProof) -> Vec<u8> {
    match aggregate {
        SignedAggregateAndProof::Phase0(value) => value.to_ssz(),
        SignedAggregateAndProof::Electra(value) => value.to_ssz(),
        SignedAggregateAndProof::Gloas(value) => value.to_ssz(),
    }
}

static TARGETS: &[Target] = &[
    Target {
        topic: topics::BEACON_BLOCK,
        containers: &[("SignedBeaconBlock", &ForkName::ALL)],
        round_trip: |config, _, bytes| gossip(config, topics::BEACON_BLOCK, bytes),
        // `SignedBeaconBlock`: offset to `message`, whose first field is `slot`.
        slot_at: Some(|bytes| u32_at(bytes, 0)),
    },
    Target {
        topic: topics::BEACON_AGGREGATE_AND_PROOF,
        containers: &[("SignedAggregateAndProof", &ForkName::ALL)],
        round_trip: |config, _, bytes| gossip(config, topics::BEACON_AGGREGATE_AND_PROOF, bytes),
        // `message` offset, then `AggregateAndProof`'s `aggregate` offset eight
        // bytes in, then `Attestation`'s `data.slot` after its bits offset.
        slot_at: Some(|bytes| {
            let message = u32_at(bytes, 0)?;
            let aggregate = message.checked_add(u32_at(bytes, message.checked_add(8)?)?)?;
            aggregate.checked_add(4)
        }),
    },
    Target {
        topic: topics::ATTESTER_SLASHING,
        containers: &[("AttesterSlashing", &ForkName::ALL)],
        round_trip: |config, _, bytes| gossip(config, topics::ATTESTER_SLASHING, bytes),
        // `attestation_1` offset, then `data.slot` after its indices offset.
        slot_at: Some(|bytes| u32_at(bytes, 0)?.checked_add(4)),
    },
    Target {
        topic: topics::VOLUNTARY_EXIT,
        containers: &[("SignedVoluntaryExit", &ForkName::ALL)],
        round_trip: |config, _, bytes| gossip(config, topics::VOLUNTARY_EXIT, bytes),
        slot_at: None,
    },
    Target {
        topic: topics::PROPOSER_SLASHING,
        containers: &[("ProposerSlashing", &ForkName::ALL)],
        round_trip: |config, _, bytes| gossip(config, topics::PROPOSER_SLASHING, bytes),
        slot_at: None,
    },
    Target {
        topic: topics::BLS_TO_EXECUTION_CHANGE,
        containers: &[("SignedBLSToExecutionChange", CAPELLA_ON)],
        round_trip: |config, _, bytes| gossip(config, topics::BLS_TO_EXECUTION_CHANGE, bytes),
        slot_at: None,
    },
    Target {
        topic: topics::SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF,
        containers: &[("SignedContributionAndProof", ALTAIR_ON)],
        round_trip: |config, _, bytes| {
            gossip(config, topics::SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF, bytes)
        },
        slot_at: None,
    },
    Target {
        topic: "sync_committee_{subnet_id}",
        containers: &[("SyncCommitteeMessage", ALTAIR_ON)],
        round_trip: |_, _, bytes| decode::decode_sync_committee_message(bytes).map(|v| v.to_ssz()),
        slot_at: None,
    },
    Target {
        topic: "beacon_attestation_{subnet_id}",
        containers: &[
            ("Attestation", PRE_ELECTRA),
            ("SingleAttestation", ELECTRA_ON),
        ],
        round_trip: |_, fork, bytes| {
            decode::decode_attestation(fork, bytes).map(|decoded| match decoded {
                decode::Attestation::Phase0(value) => value.to_ssz(),
                decode::Attestation::Electra(value) => value.to_ssz(),
            })
        },
        slot_at: None,
    },
    Target {
        topic: "data_column_sidecar_{subnet_id}",
        containers: &[("DataColumnSidecar", &[ForkName::Fulu, ForkName::Gloas])],
        round_trip: |_, fork, bytes| {
            decode::decode_data_column_sidecar(fork, bytes).map(|v| v.to_ssz())
        },
        slot_at: None,
    },
    Target {
        topic: "execution_payload",
        containers: &[("SignedExecutionPayloadEnvelope", GLOAS)],
        round_trip: |_, _, bytes| {
            decode::decode_execution_payload_envelope(bytes).map(|v| v.to_ssz())
        },
        slot_at: None,
    },
    Target {
        topic: "payload_attestation_message",
        containers: &[("PayloadAttestationMessage", GLOAS)],
        round_trip: |_, _, bytes| {
            decode::decode_payload_attestation_message(bytes).map(|v| v.to_ssz())
        },
        slot_at: None,
    },
    Target {
        topic: "execution_payload_bid",
        containers: &[("SignedExecutionPayloadBid", GLOAS)],
        round_trip: |_, _, bytes| decode::decode_execution_payload_bid(bytes).map(|v| v.to_ssz()),
        slot_at: None,
    },
    Target {
        topic: "proposer_preferences",
        containers: &[("SignedProposerPreferences", GLOAS)],
        round_trip: |_, _, bytes| decode::decode_proposer_preferences(bytes).map(|v| v.to_ssz()),
        slot_at: None,
    },
];

/// One fixture case, ready to decode at its fork.
struct Seed {
    target: &'static Target,
    fork: ForkName,
    /// `<fork>/ssz_static/<container>/<suite>/<case>`, for reports.
    case: String,
    bytes: Vec<u8>,
}

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../consensus-spec-tests/tests/mainnet")
}

/// Every case of every target's containers, slot moved inside its fork.
static SEEDS: LazyLock<Vec<Seed>> = LazyLock::new(|| {
    let config = config();
    let root = fixtures_root();
    let mut seeds = Vec::new();
    for target in TARGETS {
        for &(container, forks) in target.containers {
            for &fork in forks {
                let dir = root.join(fork.as_str()).join("ssz_static").join(container);
                for case_dir in case_dirs(&dir) {
                    let compressed = std::fs::read(case_dir.join("serialized.ssz_snappy"))
                        .expect("every ssz_static case has serialized.ssz_snappy");
                    let mut bytes = snap::raw::Decoder::new()
                        .decompress_vec(&compressed)
                        .expect("fixture bytes are raw snappy");
                    if let Some(slot_at) = target.slot_at {
                        let at = slot_at(&bytes).expect("a fixture's offsets are in range");
                        let slot = config.fork_epoch(fork) * preset::slots_per_epoch() + 1;
                        bytes[at..at + 8].copy_from_slice(&slot.to_le_bytes());
                    }
                    let case = case_dir
                        .strip_prefix(&root)
                        .unwrap_or(&case_dir)
                        .display()
                        .to_string();
                    seeds.push(Seed {
                        target,
                        fork,
                        case,
                        bytes,
                    });
                }
            }
        }
    }
    seeds
});

/// `<container>/<suite>/<case>` directories, sorted so seed indices are stable
/// across runs (an `EPHYRA_REPLAY` line names a seed by index).
fn case_dirs(container: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(container)
        .into_iter()
        .flatten()
        .flatten()
        .flat_map(|suite| {
            std::fs::read_dir(suite.path())
                .into_iter()
                .flatten()
                .flatten()
        })
        .map(|case| case.path())
        .filter(|path| path.join("serialized.ssz_snappy").is_file())
        .collect();
    dirs.sort();
    dirs
}

/// A byte-level edit. Positions are taken modulo the payload's length, so
/// every mutation applies to every payload and shrinks toward position 0.
#[derive(Clone, Debug, ephyra::Arbitrary)]
enum Mutation {
    /// Overwrite one byte with a value SSZ treats specially somewhere: a
    /// boolean's 0/1 and the 2 past it, a bitlist delimiter's high bit.
    Set(
        #[ephyra(gen = gens::int(0usize..=1 << 20))] usize,
        #[ephyra(gen = gens::pick_from(vec![0u8, 1, 2, 0x7f, 0x80, 0xff]))] u8,
    ),
    /// XOR one byte with a non-zero mask.
    Flip(
        #[ephyra(gen = gens::int(0usize..=1 << 20))] usize,
        #[ephyra(gen = gens::int(1u8..=255))] u8,
    ),
    /// Add a small amount to the four-byte word at a four-byte boundary,
    /// which is where the offsets of a variable-size container sit.
    Nudge(
        #[ephyra(gen = gens::int(0usize..=1 << 20))] usize,
        #[ephyra(gen = gens::int(-8i32..=8))] i32,
    ),
    /// Cut the payload short.
    Truncate(#[ephyra(gen = gens::int(0usize..=1 << 20))] usize),
    /// Remove a few bytes.
    Remove(
        #[ephyra(gen = gens::int(0usize..=1 << 20))] usize,
        #[ephyra(gen = gens::int(1usize..=8))] usize,
    ),
    /// Insert a few bytes.
    Insert(
        #[ephyra(gen = gens::int(0usize..=1 << 20))] usize,
        #[ephyra(gen = gens::vec(gens::int(0u8..=255)).len(1..=8))] Vec<u8>,
    ),
    /// Add bytes at the end, where the last variable field (often a list or a
    /// bitlist) ends.
    Append(#[ephyra(gen = gens::vec(gens::int(0u8..=255)).len(1..=16))] Vec<u8>),
}

fn mutate(mut bytes: Vec<u8>, mutations: &[Mutation]) -> Vec<u8> {
    for mutation in mutations {
        let len = bytes.len();
        match mutation {
            Mutation::Set(at, value) if len > 0 => bytes[at % len] = *value,
            Mutation::Flip(at, mask) if len > 0 => bytes[at % len] ^= mask,
            Mutation::Nudge(at, delta) if len >= 4 => {
                let at = (at % (len - 3)) & !3;
                let word = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
                let nudged = word.wrapping_add_signed(*delta);
                bytes[at..at + 4].copy_from_slice(&nudged.to_le_bytes());
            }
            Mutation::Truncate(at) => bytes.truncate(at % (len + 1)),
            Mutation::Remove(at, count) if len > 0 => {
                let at = at % len;
                bytes.drain(at..(at + count).min(len));
            }
            Mutation::Insert(at, inserted) => {
                let at = at % (len + 1);
                bytes.splice(at..at, inserted.iter().copied());
            }
            Mutation::Append(appended) => bytes.extend_from_slice(appended),
            Mutation::Set(..) | Mutation::Flip(..) | Mutation::Nudge(..) | Mutation::Remove(..) => {
            }
        }
    }
    bytes
}

fn hex_window(bytes: &[u8]) -> String {
    let shown = bytes.len().min(96);
    let suffix = if bytes.len() > shown { "..." } else { "" };
    format!(
        "{}{suffix} ({} bytes)",
        hex::encode(&bytes[..shown]),
        bytes.len()
    )
}

/// Every fixture case decodes through its topic's decoder and encodes back to
/// its own bytes: the harness's own check (the seeds and the slot placement
/// are right), and the decoders' fork dispatch on valid input.
#[test]
#[cfg_attr(
    not(feature = "beacon-spec-tests"),
    ignore = "needs the ssz_static fixtures; run `make consensus-spec-tests`"
)]
fn every_fixture_decodes_through_its_gossip_decoder() {
    let config = config();
    for target in TARGETS {
        let count = SEEDS
            .iter()
            .filter(|seed| std::ptr::eq(seed.target, target))
            .count();
        assert!(
            count > 0,
            "no fixture cases for `{}` under {}",
            target.topic,
            fixtures_root().display()
        );
    }
    for seed in SEEDS.iter() {
        let decoded = (seed.target.round_trip)(&config, seed.fork, &seed.bytes);
        assert_eq!(
            decoded.as_deref(),
            Ok(seed.bytes.as_slice()),
            "{} through `{}`",
            seed.case,
            seed.target.topic
        );
    }
}

/// Whatever a peer publishes, its topic's decoder either refuses it or reads
/// a value whose encoding is exactly what was published.
#[ephyra::test(tests = 20_000)]
#[cfg_attr(
    not(feature = "beacon-spec-tests"),
    ignore = "needs the ssz_static fixtures; run `make consensus-spec-tests`"
)]
fn a_gossip_decoder_accepts_only_canonical_encodings(
    #[ephyra(gen = gens::int(0usize..=1 << 20))] seed: usize,
    #[ephyra(gen = gens::vec(ephyra::any::<Mutation>()).len(1..=4))] mutations: Vec<Mutation>,
) {
    let seed = &SEEDS[seed % SEEDS.len()];
    let bytes = mutate(seed.bytes.clone(), &mutations);
    let decoded = (seed.target.round_trip)(&config(), seed.fork, &bytes);
    ephyra::classify(decoded.is_ok(), "accepted");
    ephyra::classify(bytes == seed.bytes, "unchanged by its mutations");
    let Ok(reencoded) = decoded else {
        return;
    };
    ephyra::signature(format!("{} at {}", seed.target.topic, seed.fork));
    assert!(
        reencoded == bytes,
        "`{}` accepted a non-canonical encoding\n  seed:      {}\n  received:  {}\n  re-encoded: {}",
        seed.target.topic,
        seed.case,
        hex_window(&bytes),
        hex_window(&reencoded),
    );
}
