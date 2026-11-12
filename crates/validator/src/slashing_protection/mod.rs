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
//! - **A second process on the same directory.** [`SlashingProtection::open`]
//!   takes an exclusive lock in the validators directory for the life of the
//!   process, so a second validator client pointed at that directory refuses
//!   to start. The lock is per directory, not per key: the same keystore
//!   copied into a second directory gets a second record and a second lock.
//! - **Another chain.** The record names the chain's `genesis_validators_root`
//!   and is refused for any other.
//! - **A backward clock step or a duty schedule replaced mid-epoch**, the two
//!   in-run shapes the in-memory guards this replaces were written for.
//!
//! # What it costs
//!
//! Every write rewrites the whole record, one compact JSON file, and flushes
//! it and its directory: the cost of a slot's attestation batch or a block
//! grows with the number of keys, not with the batch, and sits on the signing
//! path, off the executor. Fine for hundreds of keys on a local disk. For
//! thousands, or on a network volume whose flush takes tens of milliseconds
//! or more, `ethlambda_validator_slashing_protection_write_seconds` is the
//! number to watch, and the directory should be a local disk.
//!
//! It cannot see keys running in another client on another machine: no record
//! kept here can. A key moved here from elsewhere must bring its history with
//! it, which is why a key with no record is refused at startup unless the
//! operator says otherwise. A key registered with no history starts as never
//! having signed: the migration window, where the key may have signed
//! elsewhere a moment ago, is doppelganger protection's to close, not this
//! record's.

pub mod file;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ethlambda_types::beacon::containers::shared::AttestationData;
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch, Root, Slot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::beacon_node::dto::encode_hex;
use crate::error::{Error, Result};

/// The handle the duty services and the keymanager share.
///
/// A `std::sync::Mutex`: every critical section is a lookup, an insert and, on
/// a change, a file write, with no `.await` inside. Async callers go through
/// [`blocking`], so neither the write nor waiting for another holder's write
/// holds up the executor.
///
/// It also carries the signal that the record has become unusable. A panic
/// while the lock is held poisons it for the life of the process, since
/// nothing here recovers a record a panic may have left half-updated in
/// memory: from then on no attestation and no block can be signed. The
/// remedy is a restart, which reads the record back from disk, where every
/// write either replaced it whole or left it alone. [`blocking`] raises the
/// signal from the access that poisons the lock, or first finds it poisoned,
/// and [`crate::run`] stops the client on it, for its supervisor to restart.
#[derive(Clone)]
pub struct SharedProtection {
    record: Arc<Mutex<SlashingProtection>>,
    unusable: CancellationToken,
}

impl SharedProtection {
    pub fn new(protection: SlashingProtection) -> Self {
        Self {
            record: Arc::new(Mutex::new(protection)),
            unusable: CancellationToken::new(),
        }
    }

    /// Lock the record on the calling thread, waiting out any other holder.
    /// For synchronous callers; an async one goes through [`blocking`].
    pub fn lock(&self) -> std::sync::LockResult<std::sync::MutexGuard<'_, SlashingProtection>> {
        self.record.lock()
    }

    /// Resolves once the record is unusable, and never on a healthy one.
    pub async fn unusable(&self) {
        self.unusable.cancelled().await;
    }
}

/// How long [`blocking`] waits for the record before refusing, and how often
/// it looks. A flush takes milliseconds on a healthy disk; a quarter of a
/// 12-second slot is what a slow one gets.
const RECORD_WAIT: std::time::Duration = std::time::Duration::from_secs(3);
const RECORD_POLL: std::time::Duration = std::time::Duration::from_millis(5);

/// Run `operation` on the record on tokio's blocking pool, and wait for it.
///
/// Every async caller goes through here, including ones that only read: the
/// mutex can be held by another caller's write, a full rewrite and two
/// flushes, and waiting for it on an executor thread would stall whatever else
/// that thread runs.
///
/// The operation's own error comes back as it is, so a caller can still tell
/// a write that failed (`Error::Io`, a disk to look at) from a record that
/// could not be reached at all (`Error::SlashingProtectionUnusable`): the
/// lock is poisoned, because an operation panicked while holding it. The call
/// whose own operation panicked sees that as the blocking task's `JoinError`
/// and is told the panic was its own; every later call is told an earlier
/// access panicked. Either way the access raises the handle's signal (see
/// [`SharedProtection`]), from the blocking task rather than from the caller,
/// who may be gone by then.
///
/// The operation runs to completion even if the caller is dropped, as a duty
/// abandoned at its deadline is: that is safe, since a record written for a
/// message that is then never signed only costs that message.
///
/// A caller that finds the record held for [`RECORD_WAIT`] is refused, and
/// the duty is not retried within the slot: the holder is a flush still
/// running, and a retry would wait on that same flush. Nothing was recorded
/// for the refused duty, so the next slot's are unaffected; the write itself
/// is not bounded, since a flush cannot be interrupted, only outwaited.
pub async fn blocking<T: Send + 'static>(
    protection: &SharedProtection,
    operation: impl FnOnce(&mut SlashingProtection) -> Result<T> + Send + 'static,
) -> Result<T> {
    let SharedProtection { record, unusable } = protection.clone();
    tokio::task::spawn_blocking(move || {
        // Declared before the guard, so on a panic in `operation` it drops
        // after the guard has poisoned the lock: nobody is told the record is
        // unusable before it is.
        let _signal = SignalIfPanicking(&unusable);
        // A bounded wait rather than `lock()`: a write normally holds the
        // record for milliseconds, so a wait this long means a flush is
        // stuck, and refusing then keeps a stuck disk from piling up one
        // blocking task per slot until the pool is full. Nothing is signed
        // on a refusal.
        let deadline = std::time::Instant::now() + RECORD_WAIT;
        let mut protection = loop {
            match record.try_lock() {
                Ok(guard) => break guard,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    unusable.cancel();
                    return Err(poisoned_earlier());
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(Error::SlashingProtectionUnusable {
                            reason: format!(
                                "the record has been held by other accesses for {} s: a write \
                                 may be stuck, or the keymanager may be busy",
                                RECORD_WAIT.as_secs()
                            ),
                        });
                    }
                    std::thread::sleep(RECORD_POLL);
                }
            }
        };
        operation(&mut protection)
    })
    .await
    .map_err(|err| {
        let reason = if err.is_panic() {
            // This call's own operation panicked, and it held the record when
            // it did: nothing else in the task can panic. Said as this
            // access's failure, since "an earlier access" would send whoever
            // reads it looking for another event. The panic's message and
            // location are what the panic hook printed, so they are not
            // repeated here.
            "this access panicked while holding the record, so no attestation or block is signed \
             until the validator client is restarted; the panic is reported just before this"
                .to_string()
        } else {
            format!("the record could not be consulted: {err}")
        };
        Error::SlashingProtectionUnusable { reason }
    })?
}

/// Raises the record's signal when dropped by a panic unwinding past it.
struct SignalIfPanicking<'a>(&'a CancellationToken);

impl Drop for SignalIfPanicking<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.cancel();
        }
    }
}

/// What a caller is told when it finds the record's lock already poisoned.
fn poisoned_earlier() -> Error {
    Error::SlashingProtectionUnusable {
        reason: "an earlier access panicked while holding the record, so no attestation or block \
                 is signed until the validator client is restarted"
            .to_string(),
    }
}

/// Whether an attestation's source epoch is at or past its target, which is
/// never valid outside genesis: with unsigned epochs, `(0, 0)` is the only
/// such pair that is. One predicate for the three places that refuse it,
/// the attestation-data check, the record and the file reader, so they
/// cannot drift.
pub(crate) fn is_impossible_source(source: Epoch, target: Epoch) -> bool {
    source >= target && source != 0
}

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

/// An EIP-3076 interchange parsed once, for [`SlashingProtection::absorb`]:
/// the chain it names and each validator's watermarks, reduced as
/// [`SlashingProtection::import`] describes.
#[derive(Debug, Clone)]
pub struct StagedHistory {
    root: Root,
    entries: Vec<(BlsPubkey, Record)>,
}

impl StagedHistory {
    /// The chain the interchange names: what a record created for it must
    /// belong to.
    pub fn root(&self) -> Root {
        self.root
    }
}

/// What [`SlashingProtection::absorb`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Absorbed {
    /// How many distinct validators the history named.
    pub named: usize,
    /// How many keys were newly registered as never having signed.
    pub registered: usize,
    /// The validators that already had a record and whose watermarks the
    /// history raised: a caller running some of them can say so.
    pub raised: Vec<BlsPubkey>,
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
        // `validate_attestation_data` refuses the shape before it reaches the
        // record; this is the record defending itself, since recording such a
        // pair would refuse every honest attestation after it.
        if is_impossible_source(source, target) {
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

    /// Both records' maxima: what an import leaves when it meets an existing
    /// record. Never less strict than either.
    fn merged(self, other: Record) -> Record {
        Record {
            block_slot: self.block_slot.max(other.block_slot),
            attestation: match (self.attestation, other.attestation) {
                (Some(ours), Some(theirs)) => Some(ours.max_with(theirs)),
                (ours, theirs) => ours.or(theirs),
            },
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
                write!(
                    f,
                    "source epoch {source} is at or after target epoch {target}"
                )
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
    /// `genesis_validators_root`, and hold its lock until the returned record is
    /// dropped.
    ///
    /// Every key in `keys` must already have a record. A key without one is
    /// refused unless `init` is set, in which case it is registered as never
    /// having signed: the operator's statement that this key has signed
    /// nothing the record should know about. A missing file is created only
    /// on the same terms, or when there are no keys at all.
    pub fn open(
        validators_dir: &Path,
        genesis_validators_root: Root,
        keys: &[BlsPubkey],
        init: bool,
    ) -> Result<Self> {
        let lock = Self::lock(validators_dir)?;
        Self::open_locked(lock, validators_dir, genesis_validators_root, keys, init)
    }

    /// Take the directory's exclusive lock ahead of [`Self::open_locked`], so
    /// it can be held from before the keys are loaded: taken only at `open`,
    /// a second process could load a key, wait for the first to delete it and
    /// exit, then take the lock and sign with a key the file no longer lists.
    pub fn lock(validators_dir: &Path) -> Result<std::fs::File> {
        file::lock(validators_dir)
    }

    /// [`Self::open`] with the lock already held, from [`Self::lock`].
    pub fn open_locked(
        lock: std::fs::File,
        validators_dir: &Path,
        genesis_validators_root: Root,
        keys: &[BlsPubkey],
        init: bool,
    ) -> Result<Self> {
        let path = validators_dir.join(file::FILE_NAME);
        let refused = |reason: String| Error::SlashingProtection {
            path: path.display().to_string(),
            reason,
        };

        let existed = file::exists(&path)?;
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
                 Start once with --init-slashing-protection only once they have signed \
                 nothing anywhere for at least two epochs: stop the client that last ran \
                 them and wait. That rules out a double vote, not a surround of an older \
                 vote; a key with a history should bring it",
                missing.len()
            )));
        }
        for key in &missing {
            debug!(
                pubkey = %encode_hex(&key.0),
                "Registering a validator with no slashing-protection history"
            );
            records.insert(*key, Record::default());
        }
        if !missing.is_empty() {
            warn!(
                registered = missing.len(),
                "Registered validators with no slashing-protection history \
                 (--init-slashing-protection); each starts as never having signed"
            );
        }
        if init && missing.is_empty() && !keys.is_empty() {
            warn!(
                "--init-slashing-protection is set but every key already has a record; remove \
                 the flag, or a keystore copied into the directory later is registered with no \
                 history without anyone noticing"
            );
        }

        // Written once whatever its state, as a probe: a filesystem that
        // refuses to flush a directory (some FUSE, CIFS and overlay mounts
        // answer EINVAL) would otherwise fail every slot's write, with the
        // records advancing in memory and nothing ever signed, and nothing at
        // startup to say why. Here it is a startup error naming the path.
        file::write(&path, genesis_validators_root, records.iter())?;
        Ok(Self {
            genesis_validators_root,
            records,
            storage: Some(Storage { path, _lock: lock }),
        })
    }

    /// Open the record in `validators_dir` without a beacon node, for the
    /// `slashing-protection` command, holding its lock until the returned record
    /// is dropped.
    ///
    /// The chain is whatever the record names. With no record yet, one is
    /// started for `create_for` if given, which is how an interchange is
    /// imported into a directory before the client first runs there; with
    /// neither, this is an error. The file itself is only written by the
    /// first change, so an import that fails, or imports nothing, leaves the
    /// directory as it found it. A record created for the wrong chain is not
    /// dangerous either: [`Self::open`] refuses it at the client's next start.
    pub fn open_offline(validators_dir: &Path, create_for: Option<Root>) -> Result<Self> {
        let lock = Self::lock(validators_dir)?;
        let path = validators_dir.join(file::FILE_NAME);
        let (genesis_validators_root, records) = if file::exists(&path)? {
            file::read(&path)?
        } else if let Some(root) = create_for {
            (root, HashMap::new())
        } else {
            return Err(Error::SlashingProtection {
                path: path.display().to_string(),
                reason: "there is no slashing-protection record in this directory".to_string(),
            });
        };
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
    /// uses [`Self::open`], and this is behind the `test-utils` feature so no
    /// production caller can reach it.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn in_memory() -> SharedProtection {
        SharedProtection::new(Self {
            genesis_validators_root: Root::ZERO,
            records: HashMap::new(),
            storage: None,
        })
    }

    /// The record's path, or `None` for the in-memory record of the tests.
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
    /// The outer `Err` is a record that could not be written, and nothing may
    /// be signed. Nothing changed either, with one exception: on
    /// [`Error::Unflushed`] the slot is on disk and in memory (see
    /// [`Self::commit`]), so a retry is refused as already proposed. Treat
    /// every `Err` as "do not sign"; none of them means the old watermark
    /// is still the one in force.
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
    /// The verdicts are in `pubkeys` order. A key listed twice is judged, at
    /// its later position, against the verdict of its earlier one, so it is
    /// refused the second time: same target as the one just staged. The outer
    /// `Err` is a record that could not be written, and none of them may be
    /// signed. Nothing changed either, with one exception: on
    /// [`Error::Unflushed`] the target is on disk and in memory (see
    /// [`Self::commit`]), so a retry is refused as already signed. Treat every
    /// `Err` as "do not sign"; none of them means the old watermarks are
    /// still the ones in force.
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

    /// Register keys with no record as never having signed, and persist them
    /// in one write.
    ///
    /// For keys added at runtime through the keymanager API, which loads a key
    /// only after this returns. A key that already has a record keeps it:
    /// registering never lowers a watermark. Returns how many were new.
    pub fn register(&mut self, pubkeys: &[BlsPubkey]) -> Result<usize> {
        self.absorb(None, pubkeys)
            .map(|absorbed| absorbed.registered)
    }

    /// The chain this record belongs to.
    pub fn genesis_validators_root(&self) -> Root {
        self.genesis_validators_root
    }

    /// Whether `pubkey` has a record.
    pub fn contains(&self, pubkey: &BlsPubkey) -> bool {
        self.records.contains_key(pubkey)
    }

    /// Every validator with a record.
    pub fn pubkeys(&self) -> Vec<BlsPubkey> {
        self.records.keys().copied().collect()
    }

    /// Merge an EIP-3076 version 5 interchange, complete or minimal, into the
    /// record, in one durable write.
    ///
    /// Each validator in it is reduced to its highest slot, source and target
    /// and merged with any existing record by taking the maximum of each, so an
    /// import never lowers a watermark, and slashable data inside it (two
    /// blocks for one slot, a surround) is absorbed rather than refused: the
    /// result is at least as strict as every message the file lists. The one
    /// shape refused is an attestation whose source is at or past its target
    /// outside genesis: never valid, and read into the record it would refuse
    /// every honest attestation until the chain justified past that source.
    /// A validator it names that has no record yet is registered with the
    /// imported watermarks.
    ///
    /// All or nothing: an interchange for another chain or of another version,
    /// or one that does not parse, changes nothing. Returns how many distinct
    /// validators it named.
    pub fn import(&mut self, interchange: &str) -> Result<usize> {
        let staged = Self::stage(interchange)?;
        self.absorb(Some(&staged), &[])
            .map(|absorbed| absorbed.named)
    }

    /// Parse `interchange` into what [`Self::absorb`] takes, off any lock:
    /// its version and shape are judged here, its chain by `absorb`.
    pub fn stage(interchange: &str) -> Result<StagedHistory> {
        let (root, entries) =
            file::parse(interchange).map_err(|reason| Error::SlashingProtection {
                path: "interchange".to_string(),
                reason,
            })?;
        Ok(StagedHistory { root, entries })
    }

    /// Whether `staged` is for this record's chain, changing nothing.
    fn check_staged(&self, staged: &StagedHistory) -> Result<()> {
        if staged.root != self.genesis_validators_root {
            return Err(Error::SlashingProtection {
                path: "interchange".to_string(),
                reason: format!(
                    "it is for genesis_validators_root {}, but this record is for {}",
                    encode_hex(&staged.root.0),
                    encode_hex(&self.genesis_validators_root.0)
                ),
            });
        }
        Ok(())
    }

    /// Merge `history`, if any, as [`Self::import`] describes, and register
    /// every key in `register` that then still has no record, in one durable
    /// write: either all of it is on disk or none of it is. Reports how many
    /// validators the history named, how many keys were newly registered,
    /// and which existing records the history raised.
    ///
    /// A key in `register` that already has a record and is not in the
    /// history keeps that record, with a warning: it is what this client last
    /// signed with the key, which says nothing about what the key signed
    /// elsewhere since. Nothing is written when no watermark would change,
    /// so absorbing a history twice costs one write, not two.
    pub fn absorb(
        &mut self,
        history: Option<&StagedHistory>,
        register: &[BlsPubkey],
    ) -> Result<Absorbed> {
        let mut staged: HashMap<BlsPubkey, Record> = HashMap::new();
        if let Some(history) = history {
            self.check_staged(history)?;
            for (pubkey, imported) in &history.entries {
                let current = staged
                    .get(pubkey)
                    .or_else(|| self.records.get(pubkey))
                    .copied()
                    .unwrap_or_default();
                staged.insert(*pubkey, current.merged(*imported));
            }
        }
        let named = staged.len();
        let mut registered = 0;
        for pubkey in register {
            if staged.contains_key(pubkey) {
                continue;
            }
            if self.records.contains_key(pubkey) {
                warn!(
                    pubkey = %encode_hex(&pubkey.0),
                    "Registering a validator that already has a slashing-protection record and \
                     brought no history; it continues from what this client last signed with it"
                );
                continue;
            }
            staged.insert(*pubkey, Record::default());
            registered += 1;
        }
        staged.retain(|pubkey, record| self.records.get(pubkey) != Some(record));
        let raised = staged
            .keys()
            .filter(|pubkey| self.records.contains_key(*pubkey))
            .copied()
            .collect();
        if !staged.is_empty() {
            self.commit(staged)?;
        }
        Ok(Absorbed {
            named,
            registered,
            raised,
        })
    }

    /// The records of `pubkeys` as a minimal EIP-3076 version 5 interchange.
    ///
    /// A key with no record is left out rather than listed as never having
    /// signed: an empty entry would tell the importer something this client
    /// does not know. A key listed twice is exported once: an interchange that
    /// names a validator twice is refused by stricter importers, this client's
    /// own record reader among them.
    pub fn export(&self, pubkeys: &[BlsPubkey]) -> Result<String> {
        let mut seen = HashSet::with_capacity(pubkeys.len());
        let selected = pubkeys
            .iter()
            .filter(|pubkey| seen.insert(**pubkey))
            .filter_map(|pubkey| self.records.get_key_value(pubkey));
        file::render(self.genesis_validators_root, selected).map_err(|err| {
            Error::SlashingProtection {
                path: "interchange".to_string(),
                reason: format!("could not encode the export: {err}"),
            }
        })
    }

    /// Apply `changes` to the record: written to disk first, and taken into
    /// memory only once the write has succeeded, so a failed write leaves both
    /// as they were and nothing is signed. One failure is the exception: a
    /// write that replaced the file but could not flush the directory
    /// ([`Error::Unflushed`]) has the new watermarks on disk, perhaps only
    /// until a power loss, and memory takes them too, so that what this
    /// process holds is never weaker than what a reader of the file sees.
    /// Nothing is signed on that path either.
    fn commit(&mut self, changes: HashMap<BlsPubkey, Record>) -> Result<()> {
        if let Some(storage) = &self.storage {
            // What the record will hold, written without copying it: every
            // unchanged entry, then the changed ones.
            let next = self
                .records
                .iter()
                .filter(|(pubkey, _)| !changes.contains_key(*pubkey))
                .chain(changes.iter());
            let _timing = crate::metrics::time_slashing_protection_write();
            if let Err(err) = file::write(&storage.path, self.genesis_validators_root, next) {
                crate::metrics::inc_slashing_protection_write_failures();
                if matches!(err, Error::Unflushed { .. }) {
                    self.records.extend(changes);
                }
                return Err(err);
            }
        }
        self.records.extend(changes);
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

    /// What [`SlashingProtection::in_memory`] shares, held directly.
    fn memory() -> SlashingProtection {
        SlashingProtection {
            genesis_validators_root: Root::ZERO,
            records: HashMap::new(),
            storage: None,
        }
    }

    fn open(dir: &Path, keys: &[u8], init: bool) -> Result<SlashingProtection> {
        let keys: Vec<BlsPubkey> = keys.iter().map(|byte| pubkey(*byte)).collect();
        SlashingProtection::open(dir, root(0x42), &keys, init)
    }

    /// Whether the permission-based failure tests can run: root bypasses
    /// directory permissions, so as root the write they expect to fail
    /// succeeds. Docker CI commonly runs as root.
    #[cfg(unix)]
    fn running_as_root() -> bool {
        // SAFETY: `geteuid` reads a process attribute and cannot fail.
        unsafe { libc::geteuid() == 0 }
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

        if running_as_root() {
            eprintln!("skipped: root bypasses directory permissions");
            return;
        }
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

    /// The lock is on the directory, so a second opener of the same one is
    /// refused, with nothing beside the record an operator could delete to
    /// get around it.
    #[test]
    fn a_second_opener_of_the_same_directory_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let _first = open(dir.path(), &[1], true).expect("init");

        let err = open(dir.path(), &[1], false).expect_err("locked");
        assert!(
            err.to_string().contains("in use by another process"),
            "{err}"
        );
        assert!(
            !dir.path().join("slashing_protection.lock").exists(),
            "no lock file to delete"
        );
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

    /// A key registered with no history, at startup or at runtime, starts as
    /// never having signed: slot 0 and epoch 0 are signable once.
    #[test]
    fn a_key_registered_with_no_history_starts_as_never_signed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut protection = open(dir.path(), &[1], true).expect("init");
        protection.register(&[pubkey(2)]).expect("register");

        for key in [1, 2] {
            assert!(propose(&mut protection, key, 0).is_ok(), "key {key}");
            assert!(propose(&mut protection, key, 0).is_err(), "key {key}");
            assert!(
                attest(&mut protection, key, &data(0, 0, 0, 0xaa)).is_ok(),
                "key {key}"
            );
            assert!(
                attest(&mut protection, key, &data(0, 0, 0, 0xbb)).is_err(),
                "key {key}"
            );
        }
    }

    /// A symlink in the record's place, perhaps to a volume that is not
    /// mounted, must not be taken for "no record" and replaced.
    #[cfg(unix)]
    #[test]
    fn a_record_that_is_not_a_regular_file_fails_closed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(file::FILE_NAME);
        std::os::unix::fs::symlink(dir.path().join("unmounted/record.json"), &path)
            .expect("symlinks");

        let err = open(dir.path(), &[], true).expect_err("a dangling symlink");
        assert!(err.to_string().contains("not a regular file"), "{err}");
        assert!(
            std::fs::symlink_metadata(&path)
                .expect("still there")
                .file_type()
                .is_symlink(),
            "the symlink must not have been replaced"
        );
    }

    /// A minimal interchange for `key` on `root`.
    fn interchange(root_byte: u8, key: u8, slot: Slot, source: Epoch, target: Epoch) -> String {
        format!(
            r#"{{"metadata":{{"interchange_format_version":"5","genesis_validators_root":"{}"}},"data":[{{"pubkey":"{}","signed_blocks":[{{"slot":"{slot}"}}],"signed_attestations":[{{"source_epoch":"{source}","target_epoch":"{target}"}}]}}]}}"#,
            encode_hex(&root(root_byte).0),
            encode_hex(&pubkey(key).0)
        )
    }

    #[test]
    fn an_import_raises_the_watermarks_and_survives_a_restart() {
        let dir = tempfile::tempdir().expect("temp dir");
        {
            let mut protection = open(dir.path(), &[], false).expect("opens");
            assert_eq!(
                protection
                    .import(&interchange(0x42, 1, 97, 2, 3))
                    .expect("imports"),
                1
            );
        }
        let mut protection = open(dir.path(), &[1], false).expect("the imported key has a record");
        assert!(propose(&mut protection, 1, 97).is_err());
        assert!(attest(&mut protection, 1, &data(96, 2, 3, 0xaa)).is_err());
        assert!(attest(&mut protection, 1, &data(128, 3, 4, 0xaa)).is_ok());
    }

    /// A newer history imported over an older record raises it, and the raised
    /// watermarks survive a restart: the merge updates an existing entry, not
    /// only inserts a missing one.
    #[test]
    fn an_import_raises_an_existing_watermark() {
        let dir = tempfile::tempdir().expect("temp dir");
        {
            let mut protection = open(dir.path(), &[1], true).expect("init");
            propose(&mut protection, 1, 10).expect("propose");
            attest(&mut protection, 1, &data(96, 2, 3, 0xaa)).expect("attest");

            protection
                .import(&interchange(0x42, 1, 50, 4, 6))
                .expect("imports");
            assert!(propose(&mut protection, 1, 40).is_err());
            assert!(attest(&mut protection, 1, &data(160, 3, 5, 0xaa)).is_err());
        }
        let mut protection = open(dir.path(), &[1], false).expect("reopens");
        assert!(propose(&mut protection, 1, 50).is_err());
        assert!(propose(&mut protection, 1, 51).is_ok());
        assert!(attest(&mut protection, 1, &data(192, 4, 6, 0xaa)).is_err());
        assert!(attest(&mut protection, 1, &data(224, 4, 7, 0xaa)).is_ok());
    }

    /// `absorb` says which existing records it raised, and only those: a
    /// record the history creates, or leaves as it was, is not one.
    #[test]
    fn absorb_reports_the_records_it_raised() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut protection = open(dir.path(), &[1, 2], true).expect("init");
        propose(&mut protection, 1, 10).expect("propose");
        propose(&mut protection, 2, 200).expect("propose");

        let staged = SlashingProtection::stage(&interchange(0x42, 1, 50, 4, 6)).expect("stages");
        let absorbed = protection.absorb(Some(&staged), &[]).expect("absorbs");
        assert_eq!(absorbed.raised, vec![pubkey(1)]);
        assert_eq!(absorbed.named, 1);

        // Already at these watermarks: nothing raised, nothing registered.
        let again = protection
            .absorb(Some(&staged), &[pubkey(1)])
            .expect("absorbs");
        assert_eq!(
            again,
            Absorbed {
                named: 1,
                ..Absorbed::default()
            }
        );

        // A record the history creates is not a raised one.
        let fresh = SlashingProtection::stage(&interchange(0x42, 3, 50, 4, 6)).expect("stages");
        let created = protection.absorb(Some(&fresh), &[]).expect("absorbs");
        assert!(created.raised.is_empty());
        assert!(protection.contains(&pubkey(3)));
    }

    /// A source at or past its target is refused whole outside genesis, where
    /// `(0, 0)` is what every validator's first attestation looks like.
    #[test]
    fn an_import_with_a_source_past_its_target_is_refused_whole() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut protection = open(dir.path(), &[], false).expect("opens");
        let err = protection
            .import(&interchange(0x42, 1, 97, 5, 2))
            .expect_err("source past target");
        assert!(err.to_string().contains("at or after"), "{err}");
        protection
            .import(&interchange(0x42, 1, 97, 5, 5))
            .expect_err("source at target");
        assert!(protection.is_empty(), "nothing of a refused import is held");

        protection
            .import(&interchange(0x42, 1, 0, 0, 0))
            .expect("the genesis attestation imports");
        assert!(attest(&mut protection, 1, &data(32, 0, 1, 0xaa)).is_ok());
    }

    /// An older history imported over a newer record must not lower it.
    #[test]
    fn an_import_never_lowers_a_watermark() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut protection = open(dir.path(), &[1], true).expect("init");
        propose(&mut protection, 1, 200).expect("propose");
        attest(&mut protection, 1, &data(320, 9, 10, 0xaa)).expect("attest");

        protection
            .import(&interchange(0x42, 1, 97, 2, 3))
            .expect("imports");
        assert!(propose(&mut protection, 1, 150).is_err());
        assert!(attest(&mut protection, 1, &data(160, 4, 5, 0xaa)).is_err());
    }

    #[test]
    fn an_import_for_another_chain_changes_nothing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut protection = open(dir.path(), &[], false).expect("opens");
        let err = protection
            .import(&interchange(0x99, 1, 97, 2, 3))
            .expect_err("another chain");
        assert!(err.to_string().contains("genesis_validators_root"), "{err}");
        assert!(protection.is_empty());
    }

    #[test]
    fn an_export_lists_only_keys_with_a_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut protection = open(dir.path(), &[1], true).expect("init");
        propose(&mut protection, 1, 97).expect("propose");

        let exported = protection.export(&[pubkey(1), pubkey(2)]).expect("exports");
        let json: serde_json::Value = serde_json::from_str(&exported).expect("json");
        assert_eq!(json["data"].as_array().expect("array").len(), 1);
        assert_eq!(json["data"][0]["signed_blocks"][0]["slot"], "97");

        // And it imports back into a fresh record as the same watermarks.
        let other = tempfile::tempdir().expect("temp dir");
        let mut fresh = open(other.path(), &[], false).expect("opens");
        fresh.import(&exported).expect("round trip");
        assert!(propose(&mut fresh, 1, 97).is_err());
    }

    /// A key requested twice is exported once: this client's own record
    /// reader refuses a file naming a validator twice, and so may others'.
    #[test]
    fn an_export_lists_a_key_requested_twice_once() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut protection = open(dir.path(), &[1], true).expect("init");
        propose(&mut protection, 1, 97).expect("propose");

        let exported = protection.export(&[pubkey(1), pubkey(1)]).expect("exports");
        let json: serde_json::Value = serde_json::from_str(&exported).expect("json");
        assert_eq!(json["data"].as_array().expect("array").len(), 1);

        let other = tempfile::tempdir().expect("temp dir");
        let mut fresh = open(other.path(), &[], false).expect("opens");
        fresh.import(&exported).expect("round trip");
        assert!(propose(&mut fresh, 1, 97).is_err());
    }

    /// An export writes nothing to the validators directory, and the lock is
    /// an `flock` on the directory itself, which a read-only descriptor can
    /// take: keys mounted read-only can still hand their history over.
    #[cfg(unix)]
    #[test]
    fn an_export_needs_no_writable_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        if running_as_root() {
            eprintln!("skipped: root bypasses directory permissions");
            return;
        }
        let dir = tempfile::tempdir().expect("temp dir");
        let mut protection = open(dir.path(), &[1], true).expect("init");
        propose(&mut protection, 1, 97).expect("propose");
        drop(protection);

        let read_only = std::fs::Permissions::from_mode(0o500);
        std::fs::set_permissions(dir.path(), read_only).expect("chmod");
        let exported = SlashingProtection::open_offline(dir.path(), None)
            .and_then(|protection| protection.export(&[pubkey(1)]));
        let writable = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(dir.path(), writable).expect("chmod back");

        let exported = exported.expect("locks, reads and exports with no write access");
        let json: serde_json::Value = serde_json::from_str(&exported).expect("json");
        assert_eq!(json["data"][0]["signed_blocks"][0]["slot"], "97");
    }

    #[test]
    fn opening_offline_needs_a_record_or_a_chain_to_create_one_for() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(file::FILE_NAME);
        SlashingProtection::open_offline(dir.path(), None).expect_err("nothing to open");
        let mut created =
            SlashingProtection::open_offline(dir.path(), Some(root(0x42))).expect("creates");
        assert_eq!(created.genesis_validators_root(), root(0x42));
        // Nothing is on disk until something is recorded, so an import that
        // fails leaves no record behind for a chain nothing then runs on.
        assert!(!path.exists(), "the record is not written at open");
        created
            .import(&interchange(0x42, 1, 97, 2, 3))
            .expect("imports");
        assert!(path.exists(), "the first change writes the record");
        drop(created);
        let reopened = SlashingProtection::open_offline(dir.path(), Some(root(0x99)))
            .expect("an existing record keeps its own chain");
        assert_eq!(reopened.genesis_validators_root(), root(0x42));
    }

    /// Importing a history twice is the same as importing it once: the merge
    /// takes maxima, so the second pass changes nothing.
    #[test]
    fn an_import_is_idempotent() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut protection = open(dir.path(), &[], false).expect("opens");
        let history = interchange(0x42, 1, 97, 2, 3);
        protection.import(&history).expect("imports");
        let once = protection.export(&[pubkey(1)]).expect("exports");
        assert_eq!(protection.import(&history).expect("imports again"), 1);
        let twice = protection.export(&[pubkey(1)]).expect("exports");
        assert_eq!(once, twice);
        assert!(propose(&mut protection, 1, 97).is_err());
        assert!(propose(&mut protection, 1, 98).is_ok());
    }

    #[test]
    fn an_empty_interchange_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut protection = open(dir.path(), &[], false).expect("opens");
        for text in ["", "{}", "[]"] {
            protection.import(text).expect_err("not an interchange");
            SlashingProtection::stage(text).expect_err("not an interchange");
        }
        assert!(protection.is_empty());
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

    // A poisoned record.

    /// How long a test waits for a signal that should have been raised.
    const RAISED: std::time::Duration = std::time::Duration::from_secs(5);
    /// How long a test watches for a signal that should not be.
    const QUIET: std::time::Duration = std::time::Duration::from_millis(20);

    /// Poisoned the way a bug would poison it: a panic while the lock is
    /// held. Around [`blocking`], so nothing has observed it yet.
    fn poison(protection: &SharedProtection) {
        let held = protection.clone();
        std::thread::spawn(move || {
            let _guard = held.lock().expect("not poisoned yet");
            panic!("a bug while holding the record");
        })
        .join()
        .expect_err("the thread panics");
    }

    /// The access whose own operation panics is told the panic was its own,
    /// and only the ones after it that an earlier access panicked: the same
    /// wording for both points the first at an event that never happened. It
    /// also raises the signal the client stops on, with nothing else having
    /// to touch the record first.
    #[tokio::test]
    async fn the_access_that_panics_is_told_so_and_raises_the_signal() {
        let protection = SlashingProtection::in_memory();
        blocking(&protection, |_| Ok(()))
            .await
            .expect("a healthy record answers");
        tokio::time::timeout(QUIET, protection.unusable())
            .await
            .expect_err("a healthy record raises nothing");

        let own = blocking(&protection, |_| -> Result<()> {
            panic!("a bug in the record")
        })
        .await
        .expect_err("the operation panicked");
        assert!(
            matches!(own, Error::SlashingProtectionUnusable { .. }),
            "got {own}"
        );
        assert!(!own.is_retryable(), "nothing to try again");
        assert!(own.to_string().contains("this access panicked"), "{own}");
        tokio::time::timeout(RAISED, protection.unusable())
            .await
            .expect("the panicking access raises the signal");

        let later = blocking(&protection, |_| Ok(()))
            .await
            .expect_err("the record is poisoned")
            .to_string();
        assert!(later.contains("an earlier access panicked"), "{later}");
    }

    /// A lock poisoned without anyone seeing it raises nothing until an
    /// access finds it so, and that access raises the signal.
    #[tokio::test]
    async fn the_access_that_finds_the_record_poisoned_raises_the_signal() {
        let protection = SlashingProtection::in_memory();
        poison(&protection);
        tokio::time::timeout(QUIET, protection.unusable())
            .await
            .expect_err("nothing has looked at the record yet");

        blocking(&protection, |_| Ok(()))
            .await
            .expect_err("the record is poisoned");
        tokio::time::timeout(RAISED, protection.unusable())
            .await
            .expect("the access that found it raises the signal");
    }

    /// The signal comes from the blocking task, not from the caller awaiting
    /// it: a duty abandoned at its deadline drops the caller and leaves the
    /// task running, and a panic after that must still stop the client.
    #[tokio::test]
    async fn the_signal_is_raised_even_when_the_caller_is_gone() {
        let protection = SlashingProtection::in_memory();
        let (release, held) = std::sync::mpsc::channel::<()>();
        let call = blocking(&protection, move |_| -> Result<()> {
            held.recv().expect("released");
            panic!("a bug after the caller left")
        });
        // Polled, so the task is running, then dropped at the timeout.
        tokio::time::timeout(QUIET, call)
            .await
            .expect_err("the operation is still held");

        release.send(()).expect("the task is still running");
        tokio::time::timeout(RAISED, protection.unusable())
            .await
            .expect("the task itself raises the signal");
    }
}
