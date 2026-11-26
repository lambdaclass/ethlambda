//! Property tests for slashing protection (`src/slashing_protection/`), over
//! random sequences of what a validator client does with it: propose, attest
//! in batches (a key listed twice included), ask before proposing, restart,
//! move to a fresh directory through an EIP-3076 export and import, import a
//! history from elsewhere, and register a key.
//!
//! Two oracles, neither derived from the code under test:
//!
//! - **Safety**, from the consensus specs' slashing conditions
//!   (`is_slashable_attestation_data`, and a proposer slashing's "two blocks
//!   for one slot"): nothing the record lets a key sign forms a slashable pair
//!   with anything else that key signed, here or in an imported history.
//! - **Exactness**, from the rule the module documents (EIP-3076's minimal
//!   variant): a watermark model, kept independently, must give every verdict
//!   the record gives, so honest messages are not refused either.
//!
//! The record is the real one, written to a temporary directory and read back
//! on every restart, so both oracles hold across the file as well. Driven by
//! ephyra; see `docs/property_testing.md`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ephyra::{GenExt as _, gens};
use ethlambda_types::beacon::containers::shared::{AttestationData, Checkpoint};
use ethlambda_types::beacon::primitives::{BlsPubkey, H256, Root};
use ethlambda_validator::slashing_protection::{Refusal, SlashingProtection};

const GENESIS_VALIDATORS_ROOT: Root = H256([0x42; 32]);

/// Keys 0..=2 are registered when the record is created; key 3 is not, until
/// an import or a registration names it.
const KEYS: u8 = 4;
const REGISTERED_AT_START: u8 = 3;

fn pubkey(key: u8) -> BlsPubkey {
    BlsPubkey([key + 1; 48])
}

fn key_gen() -> impl ephyra::Gen<Value = u8> + Clone {
    gens::int(0u8..KEYS)
}

/// Small ranges, so repeats, equal targets and surrounds are common.
fn slot_gen() -> impl ephyra::Gen<Value = u64> + Clone {
    gens::int(0u64..=24)
}
fn epoch_gen() -> impl ephyra::Gen<Value = u64> + Clone {
    gens::int(0u64..=10)
}

/// `(source, target)`: mostly the shape an honest vote has (target one to four
/// epochs past source), which is what makes a later lower source a surround,
/// and sometimes any two epochs, including the impossible source-past-target.
fn vote_gen() -> ephyra::BoxGen<(u64, u64)> {
    gens::frequency(vec![
        (
            4,
            gens::dependent(epoch_gen(), |&source| gens::int(source + 1..=source + 4)).boxed(),
        ),
        (1, (epoch_gen(), epoch_gen()).boxed()),
    ])
    .boxed()
}

/// A validator in an imported history: its blocks and attestations, as a
/// complete EIP-3076 interchange lists them.
#[derive(Clone, Debug, ephyra::Arbitrary)]
struct History {
    #[ephyra(gen = key_gen())]
    key: u8,
    #[ephyra(gen = gens::vec(slot_gen()).len(0..=3))]
    blocks: Vec<u64>,
    #[ephyra(gen = gens::vec(vote_gen()).len(0..=3))]
    attestations: Vec<(u64, u64)>,
}

#[derive(Clone, Debug, ephyra::Arbitrary)]
enum Op {
    Propose(
        #[ephyra(gen = key_gen())] u8,
        #[ephyra(gen = slot_gen())] u64,
    ),
    /// `check_block`: the verdict without recording anything.
    CheckBlock(
        #[ephyra(gen = key_gen())] u8,
        #[ephyra(gen = slot_gen())] u64,
    ),
    /// One slot's batch over one `AttestationData`.
    Attest(
        #[ephyra(gen = gens::vec(key_gen()).len(1..=4))] Vec<u8>,
        #[ephyra(gen = vote_gen())] (u64, u64),
    ),
    /// An honest next vote for a batch, relative to the first key's marks
    /// when the step runs: source raised by 0..=2, target past the highest by
    /// 1..=3.
    Advance(
        #[ephyra(gen = gens::vec(key_gen()).len(1..=4))] Vec<u8>,
        #[ephyra(gen = gens::int(0u64..=2))] u64,
        #[ephyra(gen = gens::int(1u64..=3))] u64,
    ),
    /// A surround attempt for one key: a target past its highest, a source
    /// below its highest by 1..=3.
    Surround(
        #[ephyra(gen = key_gen())] u8,
        #[ephyra(gen = gens::int(1u64..=3))] u64,
        #[ephyra(gen = gens::int(1u64..=3))] u64,
    ),
    /// Drop the record and open the directory again.
    Restart,
    /// Export every key, and import that into a record in a new directory.
    Migrate,
    Import(#[ephyra(gen = gens::vec(ephyra::any::<History>()).len(0..=3))] Vec<History>),
    Register(#[ephyra(gen = key_gen())] u8),
}

/// What one key has signed, by the model's reckoning.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Watermarks {
    block: Option<u64>,
    /// Highest source and highest target, each on its own.
    attestation: Option<(u64, u64)>,
}

/// The documented rule, written out independently of the record.
#[derive(Default)]
struct Model {
    /// A key with no entry is unregistered.
    keys: HashMap<u8, Watermarks>,
}

impl Model {
    fn block(&self, key: u8, slot: u64) -> Result<(), Refusal> {
        let marks = self.keys.get(&key).ok_or(Refusal::Unregistered)?;
        match marks.block {
            Some(signed) if slot <= signed => Err(Refusal::SlotNotAdvanced {
                signed,
                proposed: slot,
            }),
            _ => Ok(()),
        }
    }

    fn attestation(&self, key: u8, source: u64, target: u64) -> Result<(), Refusal> {
        let marks = self.keys.get(&key).ok_or(Refusal::Unregistered)?;
        // Source at or past target is never valid, except (0, 0) at genesis.
        if source >= target && source != 0 {
            return Err(Refusal::SourceAfterTarget { source, target });
        }
        match marks.attestation {
            Some((_, signed)) if target <= signed => Err(Refusal::TargetNotAdvanced {
                signed,
                proposed: target,
            }),
            Some((signed, _)) if source < signed => Err(Refusal::SourceRegressed {
                signed,
                proposed: source,
            }),
            _ => Ok(()),
        }
    }

    /// The key's highest source and target so far, zero if none.
    fn marks(&self, key: u8) -> (u64, u64) {
        self.keys
            .get(&key)
            .and_then(|marks| marks.attestation)
            .unwrap_or((0, 0))
    }

    fn sign_block(&mut self, key: u8, slot: u64) {
        let marks = self.keys.get_mut(&key).expect("registered");
        marks.block = Some(marks.block.map_or(slot, |signed| signed.max(slot)));
    }

    fn sign_attestation(&mut self, key: u8, source: u64, target: u64) {
        let marks = self.keys.get_mut(&key).expect("registered");
        marks.attestation = Some(match marks.attestation {
            Some((s, t)) => (s.max(source), t.max(target)),
            None => (source, target),
        });
    }
}

/// Everything a key is known to have signed: here, or in a history imported.
#[derive(Clone, Copy, Debug)]
enum Signed {
    Block {
        slot: u64,
    },
    /// `id` tells two attestations apart: each carries its own block root, so
    /// two with one target are different data, a double vote.
    Attestation {
        source: u64,
        target: u64,
        id: usize,
    },
}

/// The consensus specs' slashing conditions, for one key's two messages.
fn slashable(a: Signed, b: Signed) -> bool {
    match (a, b) {
        (Signed::Block { slot: x }, Signed::Block { slot: y }) => x == y,
        (
            Signed::Attestation {
                source: s1,
                target: t1,
                id: i1,
            },
            Signed::Attestation {
                source: s2,
                target: t2,
                id: i2,
            },
        ) => {
            let double = i1 != i2 && t1 == t2;
            let surround = (s1 < s2 && t2 < t1) || (s2 < s1 && t1 < t2);
            double || surround
        }
        _ => false,
    }
}

struct Harness {
    root: tempfile::TempDir,
    dir: PathBuf,
    generation: usize,
    record: Option<SlashingProtection>,
    model: Model,
    signed: HashMap<u8, Vec<Signed>>,
    next_id: usize,
    /// Which refusals the case saw, and whether an import raised a mark.
    refusals: Vec<&'static str>,
    imported_raise: bool,
}

impl Harness {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("a temporary directory");
        let dir = root.path().join("validators-0");
        std::fs::create_dir(&dir).unwrap();
        let keys: Vec<BlsPubkey> = (0..REGISTERED_AT_START).map(pubkey).collect();
        let record = SlashingProtection::open(&dir, GENESIS_VALIDATORS_ROOT, &keys, true)
            .expect("a fresh record opens");
        let mut model = Model::default();
        for key in 0..REGISTERED_AT_START {
            model.keys.insert(key, Watermarks::default());
        }
        Self {
            root,
            dir,
            generation: 0,
            record: Some(record),
            model,
            signed: HashMap::new(),
            next_id: 0,
            refusals: Vec::new(),
            imported_raise: false,
        }
    }

    fn note(&mut self, verdict: &Result<(), Refusal>) {
        let kind = match verdict {
            Ok(()) => return,
            Err(Refusal::TargetNotAdvanced { .. }) => "target",
            Err(Refusal::SourceRegressed { .. }) => "source",
            Err(Refusal::SlotNotAdvanced { .. }) => "slot",
            Err(Refusal::Unregistered) => "unregistered",
            Err(Refusal::SourceAfterTarget { .. }) => "impossible",
        };
        self.refusals.push(kind);
    }

    fn record(&mut self) -> &mut SlashingProtection {
        self.record.as_mut().expect("open")
    }

    fn registered(&self) -> Vec<BlsPubkey> {
        self.model.keys.keys().copied().map(pubkey).collect()
    }

    /// A message the record let `key` sign: it must not be slashable with
    /// anything `key` signed before.
    fn approved(&mut self, key: u8, message: Signed, step: usize, op: &Op) {
        let history = self.signed.entry(key).or_default();
        if let Some(earlier) = history.iter().find(|earlier| slashable(**earlier, message)) {
            ephyra::signature("signed a slashable message");
            panic!("step {step}: {op:?}: key {key} signed {message:?}, slashable with {earlier:?}");
        }
        history.push(message);
    }

    /// One slot's batch over one vote, every verdict judged against the model
    /// and every approval against the safety oracle.
    fn attest(&mut self, step: usize, op: &Op, keys: &[u8], (source, target): (u64, u64)) {
        self.next_id += 1;
        let id = self.next_id;
        let data = AttestationData {
            slot: target * 32,
            index: 0,
            beacon_block_root: H256([(id % 251) as u8; 32]),
            source: Checkpoint {
                epoch: source,
                root: Root::ZERO,
            },
            target: Checkpoint {
                epoch: target,
                root: Root::ZERO,
            },
        };
        let pubkeys: Vec<BlsPubkey> = keys.iter().copied().map(pubkey).collect();
        let verdicts = self
            .record()
            .check_and_record_attestations(&pubkeys, &data)
            .expect("the record is written");
        assert_eq!(
            verdicts.len(),
            keys.len(),
            "step {step}: one verdict per key"
        );
        for (&key, actual) in keys.iter().zip(verdicts) {
            // Judged in order, a repeated key against its own earlier verdict
            // in the batch.
            let expected = self.model.attestation(key, source, target);
            assert_eq!(
                actual, expected,
                "step {step}: {op:?}: key {key}, vote ({source}, {target})"
            );
            self.note(&actual);
            if actual.is_ok() {
                self.model.sign_attestation(key, source, target);
                let message = Signed::Attestation { source, target, id };
                self.approved(key, message, step, op);
            }
        }
    }

    fn reopen(&mut self, dir: &Path) {
        self.record = None; // releases the directory's lock
        let keys = self.registered();
        self.record = Some(
            SlashingProtection::open(dir, GENESIS_VALIDATORS_ROOT, &keys, false)
                .expect("the record reopens with every registered key"),
        );
    }

    fn step(&mut self, step: usize, op: &Op) {
        match op {
            Op::Propose(key, slot) => {
                let expected = self.model.block(*key, *slot);
                let actual = self
                    .record()
                    .check_and_record_block(&pubkey(*key), *slot)
                    .expect("the record is written");
                assert_eq!(actual, expected, "step {step}: {op:?}");
                self.note(&actual);
                if actual.is_ok() {
                    self.model.sign_block(*key, *slot);
                    self.approved(*key, Signed::Block { slot: *slot }, step, op);
                }
            }
            Op::CheckBlock(key, slot) => {
                let expected = self.model.block(*key, *slot);
                let actual = self.record().check_block(&pubkey(*key), *slot);
                assert_eq!(actual, expected, "step {step}: {op:?}");
            }
            Op::Attest(keys, vote) => self.attest(step, op, keys, *vote),
            Op::Advance(keys, raise, ahead) => {
                let (source, target) = self.model.marks(keys[0]);
                self.attest(step, op, keys, (source + raise, target + ahead));
            }
            Op::Surround(key, back, ahead) => {
                let (source, target) = self.model.marks(*key);
                let vote = (source.saturating_sub(*back), target + ahead);
                self.attest(step, op, &[*key], vote);
            }
            Op::Restart => {
                let dir = self.dir.clone();
                self.reopen(&dir);
            }
            Op::Migrate => {
                let all: Vec<BlsPubkey> = (0..KEYS).map(pubkey).collect();
                let exported = self.record().export(&all).expect("the export encodes");
                self.record = None;
                self.generation += 1;
                let dir = self
                    .root
                    .path()
                    .join(format!("validators-{}", self.generation));
                std::fs::create_dir(&dir).unwrap();
                let mut fresh = SlashingProtection::open(&dir, GENESIS_VALIDATORS_ROOT, &[], false)
                    .expect("a record with no keys opens");
                fresh.import(&exported).expect("an export imports");
                self.record = Some(fresh);
                self.dir = dir.clone();
                // And through a restart, so what was imported is what is on disk.
                self.reopen(&dir);
            }
            Op::Import(histories) => {
                let json = interchange(histories);
                let impossible = histories
                    .iter()
                    .flat_map(|h| &h.attestations)
                    .any(|&(s, t)| s >= t && s != 0);
                let result = self.record().import(&json);
                if impossible {
                    assert!(
                        result.is_err(),
                        "step {step}: {op:?}: imported an attestation with source at or past target"
                    );
                    return;
                }
                result.unwrap_or_else(|err| panic!("step {step}: {op:?}: import failed: {err:?}"));
                for history in histories {
                    let before = self.model.keys.get(&history.key).copied();
                    let marks = self.model.keys.entry(history.key).or_default();
                    if let Some(&slot) = history.blocks.iter().max() {
                        marks.block = Some(marks.block.map_or(slot, |m| m.max(slot)));
                    }
                    for &(source, target) in &history.attestations {
                        marks.attestation = Some(match marks.attestation {
                            Some((s, t)) => (s.max(source), t.max(target)),
                            None => (source, target),
                        });
                    }
                    let after = Some(*marks);
                    self.imported_raise |= before.is_some() && before != after;
                    let signed = self.signed.entry(history.key).or_default();
                    signed.extend(history.blocks.iter().map(|&slot| Signed::Block { slot }));
                    for &(source, target) in &history.attestations {
                        self.next_id += 1;
                        signed.push(Signed::Attestation {
                            source,
                            target,
                            id: self.next_id,
                        });
                    }
                }
            }
            Op::Register(key) => {
                self.record()
                    .register(&[pubkey(*key)])
                    .expect("the record is written");
                self.model.keys.entry(*key).or_default();
            }
        }
    }
}

/// A complete EIP-3076 version 5 interchange, written by hand rather than by
/// the module's own renderer.
fn interchange(histories: &[History]) -> String {
    let data: Vec<String> = histories
        .iter()
        .map(|history| {
            let blocks: Vec<String> = history
                .blocks
                .iter()
                .map(|slot| format!(r#"{{"slot":"{slot}"}}"#))
                .collect();
            let attestations: Vec<String> = history
                .attestations
                .iter()
                .map(|(s, t)| format!(r#"{{"source_epoch":"{s}","target_epoch":"{t}"}}"#))
                .collect();
            format!(
                r#"{{"pubkey":"0x{}","signed_blocks":[{}],"signed_attestations":[{}]}}"#,
                hex::encode(pubkey(history.key).0),
                blocks.join(","),
                attestations.join(",")
            )
        })
        .collect();
    format!(
        r#"{{"metadata":{{"interchange_format_version":"5","genesis_validators_root":"0x{}"}},"data":[{}]}}"#,
        hex::encode(GENESIS_VALIDATORS_ROOT.0),
        data.join(",")
    )
}

/// Each case writes the record durably (a flush per signing decision, as in
/// production), so cases are slow, around 160 ms on macOS for 40 steps: the
/// default stays small and a long hunt sets `EPHYRA_BUDGET_MS`.
#[ephyra::test(tests = 100)]
fn slashing_protection_is_safe_and_exact(
    #[ephyra(gen = gens::vec(ephyra::any::<Op>()).len(0..=40))] ops: Vec<Op>,
) {
    let mut harness = Harness::new();
    for (step, op) in ops.iter().enumerate() {
        harness.step(step, op);
    }
    // What the case reached, for the report's labels: a run where these stay
    // near zero tested little.
    let refusals = &harness.refusals;
    ephyra::classify(refusals.contains(&"target"), "refused: target not advanced");
    ephyra::classify(
        refusals.contains(&"source"),
        "refused: source regressed (surround)",
    );
    ephyra::classify(refusals.contains(&"slot"), "refused: slot not advanced");
    ephyra::classify(refusals.contains(&"unregistered"), "refused: unregistered");
    ephyra::classify(harness.imported_raise, "an import raised a watermark");
    ephyra::classify(ops.iter().any(|op| matches!(op, Op::Migrate)), "migrated");
    ephyra::classify(ops.iter().any(|op| matches!(op, Op::Restart)), "restarted");
}
