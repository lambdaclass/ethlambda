//! Slashing protection: the durable record of what each validator has signed.
//!
//! # The rule
//!
//! EIP-3076's minimal variant, per validator:
//!
//! - an attestation may be signed only if its target epoch is above the
//!   highest one signed and its source epoch is not below the highest one
//!   signed;
//! - a block may be signed only if its slot is above the highest one signed.
//!
//! That is stricter than the full slashing conditions, which would need the
//! whole signing history to evaluate: with one record per validator it cannot
//! tell "surrounds an attestation from six epochs ago" from "surrounds
//! nothing", and requiring monotonic progress makes the question unnecessary.
//! An honest validator's messages already advance this way. What the
//! strictness costs is a byte-identical re-sign after a crash, which is
//! refused; that is one missed attestation, against a slashing.
//!
//! # Order of operations
//!
//! Check, record durably, then sign. The record reaches the disk before the
//! signature exists, so a signature that escapes is always one the record
//! already accounts for, whether the process then crashes, the duty is
//! abandoned at its deadline, or the beacon node rejects it. A record that
//! cannot be written means nothing is signed.
//!
//! # What it guards against
//!
//! - **A restart.** The record outlives the process; see [`file`] for how it
//!   is written and why reading it fails closed.
//! - **A second process.** [`SlashingProtection::open`] takes an exclusive
//!   lock in the validators directory for the life of the process, so a second
//!   validator client pointed at the same keys refuses to start.
//! - **Another chain.** The record names the chain's `genesis_validators_root`
//!   and is refused for any other.
//! - **A backward clock step or a duty schedule replaced mid-epoch**, the two
//!   in-run shapes the in-memory guards this replaces were written for.
//!
//! It cannot see keys running in another client on another machine: no record
//! kept here can. A key moved here from elsewhere must bring its history with
//! it, which is why a key with no record is refused at startup unless the
//! operator says otherwise (see [`SlashingProtection::open`]).

pub mod file;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ethlambda_types::beacon::containers::shared::AttestationData;
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch, Root, Slot};
use tracing::warn;

use crate::beacon_node::dto::encode_hex;
use crate::error::{Error, Result};

/// The handle the duty services and the keymanager share.
///
/// A `std::sync::Mutex`: every critical section is a lookup, an insert and, on
/// a change, a file write, with no `.await` inside. Callers on the async duty
/// path take it inside `spawn_blocking`, so the write does not hold up the
/// executor.
pub type SharedProtection = Arc<Mutex<SlashingProtection>>;

/// The highest source and target epoch signed for one validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Signed {
    source: Epoch,
    target: Epoch,
}

impl Signed {
    /// Each epoch's maximum, so that merging two records never lowers either
    /// bar.
    fn max_with(self, other: Signed) -> Signed {
        Signed {
            source: self.source.max(other.source),
            target: self.target.max(other.target),
        }
    }
}

/// What one validator has signed: its watermarks.
///
/// `None` is "never signed", kept distinct from zero so that slot 0 and epoch
/// 0 stay signable once and only once.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Record {
    block_slot: Option<Slot>,
    attestation: Option<Signed>,
}

impl Record {
    fn check_block(&self, slot: Slot) -> std::result::Result<(), Refusal> {
        match self.block_slot {
            Some(signed) if slot <= signed => Err(Refusal::SlotNotAdvanced {
                signed,
                proposed: slot,
            }),
            _ => Ok(()),
        }
    }

    fn check_attestation(&self, data: &AttestationData) -> std::result::Result<(), Refusal> {
        let (source, target) = (data.source.epoch, data.target.epoch);
        if source > target {
            return Err(Refusal::SourceAfterTarget { source, target });
        }
        let Some(signed) = self.attestation else {
            return Ok(());
        };
        if target <= signed.target {
            return Err(Refusal::TargetNotAdvanced {
                signed: signed.target,
                proposed: target,
            });
        }
        if source < signed.source {
            return Err(Refusal::SourceRegressed {
                signed: signed.source,
                proposed: source,
            });
        }
        Ok(())
    }

    fn with_block(self, slot: Slot) -> Record {
        Record {
            block_slot: Some(self.block_slot.map_or(slot, |signed| signed.max(slot))),
            ..self
        }
    }

    fn with_attestation(self, data: &AttestationData) -> Record {
        let next = Signed {
            source: data.source.epoch,
            target: data.target.epoch,
        };
        Record {
            attestation: Some(
                self.attestation
                    .map_or(next, |signed| signed.max_with(next)),
            ),
            ..self
        }
    }
}

/// Why a message was refused.
///
/// Carried out to the caller so the log says which rule fired: a repeated
/// target usually means the clock moved or a schedule was replaced, while a
/// regressed source or an unregistered key means something stranger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The key has no record, so nothing is known about what it signed.
    ///
    /// Not reachable through ordinary operation: startup refuses a key with no
    /// record, and the keymanager registers a key before loading it. Refused
    /// rather than signed if it is ever reached, since signing with no record
    /// is exactly what this module exists to prevent.
    Unregistered,
    /// The attestation's target epoch is at or below one already signed.
    ///
    /// The double-vote shape. Equality is refused as well as regression: the
    /// same target signed twice is a double vote unless the two attestations
    /// are byte-identical, and the record deliberately does not keep enough to
    /// tell those apart.
    TargetNotAdvanced { signed: Epoch, proposed: Epoch },
    /// The attestation's source epoch is below one already signed.
    ///
    /// The surround shape: a lower source with a higher target surrounds the
    /// earlier attestation.
    SourceRegressed { signed: Epoch, proposed: Epoch },
    /// The attestation's source epoch is after its own target epoch. Never
    /// valid, and never produced by an honest beacon node.
    SourceAfterTarget { source: Epoch, target: Epoch },
    /// The block's slot is at or below one already signed.
    ///
    /// Equality is refused for the reason it is for an attestation's target,
    /// and it would not help to allow it: a block re-produced for the same
    /// slot is almost never identical, since the beacon node packs whatever
    /// attestations have arrived since.
    SlotNotAdvanced { signed: Slot, proposed: Slot },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unregistered => write!(f, "the validator has no slashing-protection record"),
            Self::TargetNotAdvanced { signed, proposed } => write!(
                f,
                "target epoch {proposed} does not advance past {signed}, already signed"
            ),
            Self::SourceRegressed { signed, proposed } => write!(
                f,
                "source epoch {proposed} is below {signed}, already signed"
            ),
            Self::SourceAfterTarget { source, target } => {
                write!(f, "source epoch {source} is after target epoch {target}")
            }
            Self::SlotNotAdvanced { signed, proposed } => write!(
                f,
                "slot {proposed} does not advance past {signed}, already signed"
            ),
        }
    }
}

/// Where the record lives, and the lock that keeps it to this process.
#[derive(Debug)]
struct Storage {
    path: PathBuf,
    /// Held, never read: dropping it releases the lock.
    _lock: std::fs::File,
}

/// Every registered validator's watermarks, and where they are kept.
///
/// Not `Clone`: one per process is the point. A copy would be a second opinion
/// about what has been signed, which is worse than none.
#[derive(Debug)]
pub struct SlashingProtection {
    genesis_validators_root: Root,
    records: HashMap<BlsPubkey, Record>,
    /// `None` only for [`Self::in_memory`].
    storage: Option<Storage>,
}

impl SlashingProtection {
    /// Open the record in `validators_dir` for the chain named by
    /// `genesis_validators_root`, and hold its lock until this is dropped.
    ///
    /// Every key in `keys` must already have a record. A key without one is
    /// refused unless `init` is set, in which case it is registered as never
    /// having signed: the operator's statement that this key has not signed
    /// anything on this chain that the record should know about. A missing file
    /// is created only on the same terms, or when there are no keys at all.
    pub fn open(
        validators_dir: &Path,
        genesis_validators_root: Root,
        keys: &[BlsPubkey],
        init: bool,
    ) -> Result<Self> {
        let lock = file::lock(validators_dir)?;
        let path = validators_dir.join(file::FILE_NAME);
        let refused = |reason: String| Error::SlashingProtection {
            path: path.display().to_string(),
            reason,
        };

        let existed = path.exists();
        let mut records = if existed {
            let (stored_root, records) = file::read(&path)?;
            if stored_root != genesis_validators_root {
                return Err(refused(format!(
                    "the record is for genesis_validators_root {}, but the beacon node is on {}; \
                     these keys' history belongs to another chain",
                    encode_hex(&stored_root.0),
                    encode_hex(&genesis_validators_root.0)
                )));
            }
            records
        } else {
            HashMap::new()
        };

        let missing: Vec<BlsPubkey> = keys
            .iter()
            .filter(|key| !records.contains_key(*key))
            .copied()
            .collect();
        if !missing.is_empty() && !init {
            let first = encode_hex(&missing[0].0);
            return Err(refused(format!(
                "{} validator key(s) have no slashing-protection record (first: {first}). \
                 Import their history from the client that last ran them, or, only if they \
                 have not signed anything for at least two epochs, start once with \
                 --init-slashing-protection",
                missing.len()
            )));
        }
        for key in &missing {
            warn!(
                pubkey = %encode_hex(&key.0),
                "Registering a validator with no slashing-protection history \
                 (--init-slashing-protection)"
            );
            records.insert(*key, Record::default());
        }

        if !existed || !missing.is_empty() {
            file::write(&path, genesis_validators_root, &records)?;
        }
        Ok(Self {
            genesis_validators_root,
            records,
            storage: Some(Storage { path, _lock: lock }),
        })
    }

    /// A record kept in memory only, with every key treated as registered on
    /// first use.
    ///
    /// For tests, here and in other crates driving the duty services: it
    /// protects within one process and nothing more, which is exactly what the
    /// in-memory guards this module replaced did. The client itself only ever
    /// uses [`Self::open`].
    pub fn in_memory() -> SharedProtection {
        Arc::new(Mutex::new(Self {
            genesis_validators_root: Root::ZERO,
            records: HashMap::new(),
            storage: None,
        }))
    }

    /// The record's path, or `None` for [`Self::in_memory`].
    pub fn path(&self) -> Option<&Path> {
        self.storage.as_ref().map(|storage| storage.path.as_path())
    }

    /// How many validators have a record.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    fn record(&self, pubkey: &BlsPubkey) -> std::result::Result<Record, Refusal> {
        match self.records.get(pubkey) {
            Some(record) => Ok(*record),
            None if self.storage.is_none() => Ok(Record::default()),
            None => Err(Refusal::Unregistered),
        }
    }

    /// Whether a block for `slot` may be signed for `pubkey`, recording
    /// nothing.
    ///
    /// For deciding before paying for a block: production costs the beacon
    /// node an execution payload build. Not a substitute for
    /// [`Self::check_and_record_block`], which is the check that counts.
    pub fn check_block(&self, pubkey: &BlsPubkey, slot: Slot) -> std::result::Result<(), Refusal> {
        self.record(pubkey)?.check_block(slot)
    }

    /// Check a block for `slot` and, if it may be signed, record it durably.
    ///
    /// The outer `Err` is a record that could not be written, in which case
    /// nothing changed and nothing may be signed.
    pub fn check_and_record_block(
        &mut self,
        pubkey: &BlsPubkey,
        slot: Slot,
    ) -> Result<std::result::Result<(), Refusal>> {
        let record = match self.record(pubkey) {
            Ok(record) => record,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Err(refusal) = record.check_block(slot) {
            return Ok(Err(refusal));
        }
        self.commit(HashMap::from([(*pubkey, record.with_block(slot))]))?;
        Ok(Ok(()))
    }

    /// Check one slot's attestations, all over `data`, and durably record every
    /// one that may be signed, in a single write.
    ///
    /// The verdicts are in `pubkeys` order. A key listed twice is judged
    /// against its first verdict, so it is refused the second time. The outer
    /// `Err` is a record that could not be written, in which case nothing
    /// changed and none of them may be signed.
    pub fn check_and_record_attestations(
        &mut self,
        pubkeys: &[BlsPubkey],
        data: &AttestationData,
    ) -> Result<Vec<std::result::Result<(), Refusal>>> {
        let mut staged: HashMap<BlsPubkey, Record> = HashMap::new();
        let verdicts = pubkeys
            .iter()
            .map(|pubkey| {
                let record = match staged.get(pubkey) {
                    Some(record) => *record,
                    None => self.record(pubkey)?,
                };
                record.check_attestation(data)?;
                staged.insert(*pubkey, record.with_attestation(data));
                Ok(())
            })
            .collect();
        if !staged.is_empty() {
            self.commit(staged)?;
        }
        Ok(verdicts)
    }

    /// Register keys with no record as never having signed, and persist.
    ///
    /// For keys added at runtime through the keymanager API, which loads a key
    /// only after this returns. A key that already has a record keeps it:
    /// registering never lowers a watermark. Returns how many were new.
    pub fn register(&mut self, pubkeys: &[BlsPubkey]) -> Result<usize> {
        let new: HashMap<BlsPubkey, Record> = pubkeys
            .iter()
            .filter(|pubkey| !self.records.contains_key(*pubkey))
            .map(|pubkey| (*pubkey, Record::default()))
            .collect();
        let count = new.len();
        if count > 0 {
            self.commit(new)?;
        }
        Ok(count)
    }

    /// Apply `changes` to the record: written to disk first, and taken into
    /// memory only once the write has succeeded, so a failed write leaves both
    /// exactly as they were.
    fn commit(&mut self, changes: HashMap<BlsPubkey, Record>) -> Result<()> {
        let Some(storage) = &self.storage else {
            self.records.extend(changes);
            return Ok(());
        };
        let mut next = self.records.clone();
        next.extend(changes);
        let _timing = crate::metrics::time_slashing_protection_write();
        file::write(&storage.path, self.genesis_validators_root, &next)
            .inspect_err(|_| crate::metrics::inc_slashing_protection_write_failures())?;
        self.records = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ethlambda_types::beacon::containers::shared::Checkpoint;
    use ethlambda_types::beacon::primitives::H256;

    use super::*;

    fn pubkey(byte: u8) -> BlsPubkey {
        BlsPubkey([byte; 48])
    }

    fn root(byte: u8) -> Root {
        H256([byte; 32])
    }

    /// An attestation at `slot` voting source `source` and target `target`.
    ///
    /// `beacon_block_root` is a parameter because the double-vote case that
    /// matters most is two attestations with one target epoch and *different*
    /// roots, which is what a re-fetch after a block arrival produces.
    fn data(slot: u64, source: Epoch, target: Epoch, block_root: u8) -> AttestationData {
        AttestationData {
            slot,
            index: 0,
            beacon_block_root: H256([block_root; 32]),
            source: Checkpoint {
                epoch: source,
                root: Root::ZERO,
            },
            target: Checkpoint {
                epoch: target,
                root: Root::ZERO,
            },
        }
    }

    /// One attestation, judged and recorded on its own.
    fn attest(
        protection: &mut SlashingProtection,
        key: u8,
        data: &AttestationData,
    ) -> std::result::Result<(), Refusal> {
        let mut verdicts = protection
            .check_and_record_attestations(&[pubkey(key)], data)
            .expect("the record is written");
        verdicts.pop().expect("one verdict")
    }

    fn propose(
        protection: &mut SlashingProtection,
        key: u8,
        slot: Slot,
    ) -> std::result::Result<(), Refusal> {
        protection
            .check_and_record_block(&pubkey(key), slot)
            .expect("the record is written")
    }

    fn memory() -> SlashingProtection {
        Arc::into_inner(SlashingProtection::in_memory())
            .expect("sole owner")
            .into_inner()
            .expect("not poisoned")
    }

    fn open(dir: &Path, keys: &[u8], init: bool) -> Result<SlashingProtection> {
        let keys: Vec<BlsPubkey> = keys.iter().map(|byte| pubkey(*byte)).collect();
        SlashingProtection::open(dir, root(0x42), &keys, init)
    }

    // The rule. Carried over from the in-memory guards this replaces.

    #[test]
    fn a_first_attestation_is_allowed() {
        assert!(attest(&mut memory(), 1, &data(96, 2, 3, 0xaa)).is_ok());
    }

    #[test]
    fn advancing_the_target_is_allowed() {
        let mut protection = memory();
        attest(&mut protection, 1, &data(96, 2, 3, 0xaa)).expect("first");
        assert!(attest(&mut protection, 1, &data(128, 3, 4, 0xbb)).is_ok());
    }

    /// The backward-clock-step case: same validator, same target epoch, a
    /// different block root because the data was re-fetched after a block
    /// arrived.
    #[test]
    fn re_attesting_one_target_with_different_data_is_refused() {
        let mut protection = memory();
        attest(&mut protection, 1, &data(96, 2, 3, 0xaa)).expect("first");
        assert_eq!(
            attest(&mut protection, 1, &data(96, 2, 3, 0xbb)),
            Err(Refusal::TargetNotAdvanced {
                signed: 3,
                proposed: 3
            })
        );
    }

    /// The mid-epoch schedule replacement case: a different slot in the same
    /// epoch is still one target epoch and still a double vote.
    #[test]
    fn a_different_slot_in_the_same_target_epoch_is_refused() {
        let mut protection = memory();
        attest(&mut protection, 1, &data(96, 2, 3, 0xaa)).expect("first");
        assert!(attest(&mut protection, 1, &data(101, 2, 3, 0xbb)).is_err());
    }

    #[test]
    fn a_regressed_target_is_refused() {
        let mut protection = memory();
        attest(&mut protection, 1, &data(128, 3, 4, 0xaa)).expect("first");
        assert!(attest(&mut protection, 1, &data(96, 2, 3, 0xbb)).is_err());
    }

    /// The surround shape: a later target with an earlier source.
    #[test]
    fn a_regressed_source_under_an_advancing_target_is_refused() {
        let mut protection = memory();
        attest(&mut protection, 1, &data(128, 3, 4, 0xaa)).expect("first");
        assert_eq!(
            attest(&mut protection, 1, &data(160, 1, 5, 0xbb)),
            Err(Refusal::SourceRegressed {
                signed: 3,
                proposed: 1
            })
        );
    }

    #[test]
    fn a_source_after_its_target_is_refused() {
        assert_eq!(
            attest(&mut memory(), 1, &data(96, 4, 3, 0xaa)),
            Err(Refusal::SourceAfterTarget {
                source: 4,
                target: 3
            })
        );
    }

    #[test]
    fn one_validator_does_not_block_another_in_the_same_epoch() {
        let mut protection = memory();
        attest(&mut protection, 1, &data(96, 2, 3, 0xaa)).expect("first validator");
        assert!(attest(&mut protection, 2, &data(101, 2, 3, 0xaa)).is_ok());
    }

    /// A refusal must not move the bar it was measured against.
    #[test]
    fn a_refusal_records_nothing() {
        let mut protection = memory();
        attest(&mut protection, 1, &data(128, 3, 4, 0xaa)).expect("first");
        attest(&mut protection, 1, &data(160, 1, 5, 0xbb)).expect_err("surround refused");
        assert!(
            attest(&mut protection, 1, &data(160, 3, 5, 0xcc)).is_ok(),
            "the refused attempt must not have lowered the recorded source"
        );
    }

    #[test]
    fn a_key_twice_in_one_batch_is_refused_the_second_time() {
        let mut protection = memory();
        let verdicts = protection
            .check_and_record_attestations(
                &[pubkey(1), pubkey(2), pubkey(1)],
                &data(96, 2, 3, 0xaa),
            )
            .expect("written");
        assert!(verdicts[0].is_ok());
        assert!(verdicts[1].is_ok());
        assert!(verdicts[2].is_err(), "the same vote twice in one batch");
    }

    #[test]
    fn proposing_the_same_slot_twice_is_refused() {
        let mut protection = memory();
        propose(&mut protection, 1, 96).expect("first");
        assert_eq!(
            propose(&mut protection, 1, 96),
            Err(Refusal::SlotNotAdvanced {
                signed: 96,
                proposed: 96
            })
        );
    }

    #[test]
    fn a_regressed_slot_is_refused_and_another_validator_is_not() {
        let mut protection = memory();
        propose(&mut protection, 1, 128).expect("first");
        assert!(propose(&mut protection, 1, 96).is_err());
        assert!(propose(&mut protection, 2, 96).is_ok());
    }

    #[test]
    fn check_block_alone_records_nothing() {
        let protection = memory();
        protection.check_block(&pubkey(1), 96).expect("allowed");
        protection
            .check_block(&pubkey(1), 96)
            .expect("still allowed, because check records nothing");
    }

    /// Slot 0 is a real slot: "never proposed" must not be spelled as zero.
    #[test]
    fn slot_zero_is_recorded_like_any_other() {
        let mut protection = memory();
        propose(&mut protection, 1, 0).expect("first");
        assert!(propose(&mut protection, 1, 0).is_err());
    }

    /// A proposal and an attestation are judged on separate watermarks: a
    /// validator can legitimately propose in an epoch it also attests in.
    #[test]
    fn a_proposal_does_not_block_an_attestation() {
        let mut protection = memory();
        propose(&mut protection, 1, 100).expect("block");
        assert!(attest(&mut protection, 1, &data(100, 2, 3, 0xaa)).is_ok());
    }

    // Durability: the record outlives the process.

    #[test]
    fn a_reopened_record_remembers_what_was_signed() {
        let dir = tempfile::tempdir().expect("temp dir");
        {
            let mut protection = open(dir.path(), &[1], true).expect("init");
            attest(&mut protection, 1, &data(96, 2, 3, 0xaa)).expect("attest");
            propose(&mut protection, 1, 97).expect("propose");
        }

        let mut protection = open(dir.path(), &[1], false).expect("reopen without init");
        assert!(
            attest(&mut protection, 1, &data(96, 2, 3, 0xbb)).is_err(),
            "the double vote from before the restart must be refused"
        );
        assert!(propose(&mut protection, 1, 97).is_err());
        assert!(attest(&mut protection, 1, &data(128, 3, 4, 0xcc)).is_ok());
    }

    #[test]
    fn a_key_with_no_record_is_refused_without_init() {
        let dir = tempfile::tempdir().expect("temp dir");
        drop(open(dir.path(), &[1], true).expect("init"));

        let err = open(dir.path(), &[1, 2], false).expect_err("key 2 has no record");
        assert!(
            err.to_string().contains("--init-slashing-protection"),
            "{err}"
        );

        drop(open(dir.path(), &[1, 2], true).expect("init registers key 2"));
        open(dir.path(), &[1, 2], false).expect("both now registered");
    }

    #[test]
    fn a_missing_file_is_created_only_with_init_or_no_keys() {
        let dir = tempfile::tempdir().expect("temp dir");
        open(dir.path(), &[1], false).expect_err("keys but no record");
        assert!(!dir.path().join(file::FILE_NAME).exists());

        drop(open(dir.path(), &[], false).expect("no keys, nothing to protect yet"));
        assert!(dir.path().join(file::FILE_NAME).exists());
    }

    #[test]
    fn init_never_lowers_an_existing_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        {
            let mut protection = open(dir.path(), &[1], true).expect("init");
            propose(&mut protection, 1, 97).expect("propose");
        }
        let mut protection = open(dir.path(), &[1], true).expect("init again");
        assert!(propose(&mut protection, 1, 97).is_err());
    }

    #[test]
    fn another_chain_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        drop(open(dir.path(), &[1], true).expect("init"));

        let err = SlashingProtection::open(dir.path(), root(0x99), &[pubkey(1)], true)
            .expect_err("another genesis_validators_root");
        assert!(err.to_string().contains("another chain"), "{err}");
    }

    #[test]
    fn a_second_process_is_refused_while_the_first_holds_the_lock() {
        let dir = tempfile::tempdir().expect("temp dir");
        let first = open(dir.path(), &[1], true).expect("first");

        let err = open(dir.path(), &[1], false).expect_err("locked");
        assert!(err.to_string().contains("another process"), "{err}");

        drop(first);
        open(dir.path(), &[1], false).expect("free once the first is gone");
    }

    /// Every damaged shape is a startup error, never an empty record.
    #[test]
    fn a_damaged_file_fails_closed() {
        let cases = [
            ("empty", String::new()),
            ("whitespace", "  \n".to_string()),
            ("truncated", r#"{"metadata":{"interchange_format_version":"5","#.to_string()),
            ("not json", "garbage".to_string()),
            (
                "wrong version",
                r#"{"metadata":{"interchange_format_version":"4","genesis_validators_root":"0x4242424242424242424242424242424242424242424242424242424242424242"},"data":[]}"#.to_string(),
            ),
        ];
        for (name, contents) in cases {
            let dir = tempfile::tempdir().expect("temp dir");
            std::fs::write(dir.path().join(file::FILE_NAME), contents).expect("write");
            assert!(
                open(dir.path(), &[], true).is_err(),
                "{name} must fail closed"
            );
        }
    }

    #[test]
    fn a_validator_listed_twice_fails_closed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let key = encode_hex(&pubkey(1).0);
        let entry = format!(r#"{{"pubkey":"{key}","signed_blocks":[],"signed_attestations":[]}}"#);
        let contents = format!(
            r#"{{"metadata":{{"interchange_format_version":"5","genesis_validators_root":"{}"}},"data":[{entry},{entry}]}}"#,
            encode_hex(&root(0x42).0)
        );
        std::fs::write(dir.path().join(file::FILE_NAME), contents).expect("write");

        let err = open(dir.path(), &[1], false).expect_err("duplicate");
        assert!(err.to_string().contains("more than once"), "{err}");
    }

    /// A write that fails changes nothing: not the file, and not what the
    /// process believes was signed.
    #[cfg(unix)]
    #[test]
    fn a_failed_write_refuses_and_changes_nothing() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("temp dir");
        let mut protection = open(dir.path(), &[1], true).expect("init");
        attest(&mut protection, 1, &data(96, 2, 3, 0xaa)).expect("attest");

        let read_only = std::fs::Permissions::from_mode(0o500);
        std::fs::set_permissions(dir.path(), read_only).expect("chmod");
        let result = protection.check_and_record_attestations(&[pubkey(1)], &data(128, 3, 4, 0xbb));
        let writable = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(dir.path(), writable).expect("chmod back");

        assert!(
            result.is_err(),
            "the write must fail in a read-only directory"
        );
        assert!(
            attest(&mut protection, 1, &data(128, 3, 4, 0xbb)).is_ok(),
            "the failed write must not have recorded target 4"
        );
    }

    #[test]
    fn the_file_is_an_eip_3076_minimal_interchange() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut protection = open(dir.path(), &[1], true).expect("init");
        attest(&mut protection, 1, &data(96, 2, 3, 0xaa)).expect("attest");
        propose(&mut protection, 1, 97).expect("propose");

        let text = std::fs::read_to_string(dir.path().join(file::FILE_NAME)).expect("read");
        let json: serde_json::Value = serde_json::from_str(&text).expect("json");
        assert_eq!(json["metadata"]["interchange_format_version"], "5");
        assert_eq!(
            json["metadata"]["genesis_validators_root"],
            encode_hex(&root(0x42).0)
        );
        let entry = &json["data"][0];
        assert_eq!(entry["pubkey"], encode_hex(&pubkey(1).0));
        assert_eq!(entry["signed_blocks"][0]["slot"], "97");
        assert_eq!(entry["signed_attestations"][0]["source_epoch"], "2");
        assert_eq!(entry["signed_attestations"][0]["target_epoch"], "3");
    }

    #[test]
    fn registering_keeps_an_existing_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut protection = open(dir.path(), &[1], true).expect("init");
        propose(&mut protection, 1, 97).expect("propose");

        assert_eq!(
            protection
                .register(&[pubkey(1), pubkey(2)])
                .expect("register"),
            1
        );
        assert!(propose(&mut protection, 1, 97).is_err());
        assert!(propose(&mut protection, 2, 97).is_ok());
    }

    #[test]
    fn an_unregistered_key_is_refused_on_a_persisted_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut protection = open(dir.path(), &[1], true).expect("init");
        assert_eq!(propose(&mut protection, 2, 97), Err(Refusal::Unregistered));
        assert_eq!(
            attest(&mut protection, 2, &data(96, 2, 3, 0xaa)),
            Err(Refusal::Unregistered)
        );
    }
}
