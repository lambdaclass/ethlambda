//! The portable operation language, consensus-rule model, and property checks.
//! No ephyra types occur here; a proptest adapter can draw the same `Trace`.

use std::collections::{BTreeMap, BTreeSet};

use ethlambda_types::beacon::containers::shared::{AttestationData, Checkpoint};
use ethlambda_types::beacon::primitives::{BlsPubkey, H256, Root};
use ethlambda_validator::slashing_protection::SlashingProtection;
use serde_json::{Value, json};

pub const MAX_KEY: u8 = 3;
pub const MAX_SLOT: u64 = 12;
pub const MAX_EPOCH: u64 = 7;
const ROOT: Root = H256([0x42; 32]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trace {
    pub ops: Vec<Op>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableCase {
    pub slot: u8,
    pub corruption: DurableCorruption,
    /// 0: open, 1: open_locked, 2: open_offline.
    pub opener: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableCorruption {
    InvalidUtf8,
    Empty,
    Truncated,
    WrongVersion,
    DuplicateKey,
    UnknownField,
    MissingField,
    ImpossibleVote,
    InvalidPubkey,
    OverflowingSlot,
}

pub const DURABLE_CORRUPTIONS: [DurableCorruption; 10] = [
    DurableCorruption::InvalidUtf8,
    DurableCorruption::Empty,
    DurableCorruption::Truncated,
    DurableCorruption::WrongVersion,
    DurableCorruption::DuplicateKey,
    DurableCorruption::UnknownField,
    DurableCorruption::MissingField,
    DurableCorruption::ImpossibleVote,
    DurableCorruption::InvalidPubkey,
    DurableCorruption::OverflowingSlot,
];

pub fn valid_durable_case(case: &DurableCase) -> bool {
    (1..=12).contains(&case.slot) && case.opener <= 2
}

fn corrupt_durable_record(original: &[u8], corruption: &DurableCorruption) -> Vec<u8> {
    match corruption {
        DurableCorruption::InvalidUtf8 => return vec![0xff, 0xfe],
        DurableCorruption::Empty => return Vec::new(),
        DurableCorruption::Truncated => return original[..original.len() / 2].to_vec(),
        _ => {}
    }
    let mut value: Value = serde_json::from_slice(original).expect("record is JSON");
    match corruption {
        DurableCorruption::WrongVersion => {
            value["metadata"]["interchange_format_version"] = json!("4");
        }
        DurableCorruption::DuplicateKey => {
            let first = value["data"][0].clone();
            value["data"].as_array_mut().unwrap().push(first);
        }
        DurableCorruption::UnknownField => {
            value["data"][0]["unknown_field"] = json!(true);
        }
        DurableCorruption::MissingField => {
            value["data"][0]
                .as_object_mut()
                .unwrap()
                .remove("signed_blocks");
        }
        DurableCorruption::ImpossibleVote => {
            value["data"][0]["signed_attestations"] =
                json!([{"source_epoch": "5", "target_epoch": "5"}]);
        }
        DurableCorruption::InvalidPubkey => {
            value["data"][0]["pubkey"] = json!("0xz");
        }
        DurableCorruption::OverflowingSlot => {
            value["data"][0]["signed_blocks"][0]["slot"] = json!("18446744073709551616");
        }
        DurableCorruption::InvalidUtf8
        | DurableCorruption::Empty
        | DurableCorruption::Truncated => unreachable!(),
    }
    serde_json::to_vec(&value).expect("mutated JSON")
}

pub fn check_durable_corruption(case: &DurableCase) {
    assert!(valid_durable_case(case));
    let dir = tempfile::tempdir().expect("temp dir");
    let key = key(1);
    let mut record = SlashingProtection::open(dir.path(), ROOT, &[key], true).expect("open");
    record
        .check_and_record_block(&key, u64::from(case.slot))
        .expect("write block")
        .expect("sign block");
    let path = record.path().unwrap().to_path_buf();
    let original = std::fs::read(&path).expect("read original");
    drop(record);

    let damaged = corrupt_durable_record(&original, &case.corruption);
    std::fs::write(&path, &damaged).expect("inject corruption");
    let result = match case.opener {
        0 => SlashingProtection::open(dir.path(), ROOT, &[key], true),
        1 => {
            let lock = SlashingProtection::lock(dir.path()).expect("directory lock");
            SlashingProtection::open_locked(lock, dir.path(), ROOT, &[key], true)
        }
        2 => SlashingProtection::open_offline(dir.path(), Some(ROOT)),
        _ => unreachable!(),
    };
    assert!(result.is_err(), "corrupt record was accepted: {case:?}");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        damaged,
        "failed open changed corrupt bytes: {case:?}"
    );

    std::fs::write(&path, original).expect("restore record");
    let mut recovered = SlashingProtection::open(dir.path(), ROOT, &[key], false).expect("recover");
    for slot in [0, u64::from(case.slot)] {
        assert!(
            recovered.check_block(&key, slot).is_err(),
            "recovery lost recorded block refusal: {case:?}"
        );
    }
    recovered
        .check_and_record_block(&key, u64::from(case.slot) + 1)
        .expect("recovery write")
        .expect("next slot remains signable");
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Register(Vec<u8>),
    Block {
        key: u8,
        slot: u64,
        root: u8,
    },
    Attest {
        keys: Vec<u8>,
        source: u64,
        target: u64,
        slot: u64,
        root: u8,
    },
    Reopen {
        mode: u8,
    },
    Import {
        entries: Vec<ImportEntry>,
        wrong_chain: bool,
    },
    Absorb {
        entries: Vec<ImportEntry>,
        register: Vec<u8>,
        wrong_chain: bool,
    },
    Export(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportEntry {
    pub key: u8,
    pub blocks: Vec<u64>,
    pub attestations: Vec<(u64, u64)>,
}

#[derive(Default, Clone, Debug)]
pub struct Stats {
    pub accepted_blocks: u64,
    pub accepted_attestations: u64,
    pub over_refused_blocks: u64,
    pub over_refused_attestations: u64,
    pub imports: u64,
    pub reopens: u64,
}

#[derive(Default)]
struct Model {
    keys: BTreeMap<u8, History>,
}

#[derive(Default)]
struct History {
    blocks: Vec<(u64, Option<u8>)>,
    attestations: Vec<Vote>,
}

#[derive(Clone, Copy)]
struct Vote {
    source: u64,
    target: u64,
    slot: u64,
    root: Option<u8>,
}

impl Model {
    fn register(&mut self, key: u8) {
        self.keys.entry(key).or_default();
    }

    fn block_slashable(&self, key: u8, slot: u64, root: u8) -> bool {
        self.keys.get(&key).is_some_and(|history| {
            history
                .blocks
                .iter()
                .any(|&(old_slot, old_root)| slot == old_slot && old_root != Some(root))
        })
    }

    fn vote_slashable(&self, key: u8, new: Vote) -> bool {
        self.keys.get(&key).is_some_and(|history| {
            history.attestations.iter().any(|old| {
                let double_vote = old.target == new.target
                    && (old.root.is_none()
                        || old.source != new.source
                        || old.slot != new.slot
                        || old.root != new.root);
                let surrounds = (old.source < new.source && new.target < old.target)
                    || (new.source < old.source && old.target < new.target);
                double_vote || surrounds
            })
        })
    }

    fn import(&mut self, entries: &[ImportEntry]) {
        for entry in entries {
            let history = self.keys.entry(entry.key).or_default();
            history
                .blocks
                .extend(entry.blocks.iter().map(|slot| (*slot, None)));
            history
                .attestations
                .extend(entry.attestations.iter().map(|&(source, target)| Vote {
                    source,
                    target,
                    slot: 0,
                    root: None,
                }));
        }
    }
}

fn key(key: u8) -> BlsPubkey {
    BlsPubkey([key; 48])
}

fn data(vote: Vote) -> AttestationData {
    AttestationData {
        slot: vote.slot,
        index: 0,
        beacon_block_root: H256([vote.root.unwrap_or(0); 32]),
        source: Checkpoint {
            epoch: vote.source,
            root: Root::ZERO,
        },
        target: Checkpoint {
            epoch: vote.target,
            root: Root::ZERO,
        },
    }
}

pub fn valid_vote(source: u64, target: u64) -> bool {
    source == 0 && target == 0 || source < target
}

fn hex_byte_repeated(byte: u8, len: usize) -> String {
    format!("0x{}", format!("{byte:02x}").repeat(len))
}

pub fn interchange(entries: &[ImportEntry], wrong_chain: bool) -> String {
    let root = if wrong_chain { 0x43 } else { 0x42 };
    let data: Vec<Value> = entries.iter().map(|entry| {
        json!({
            "pubkey": hex_byte_repeated(entry.key, 48),
            "signed_blocks": entry.blocks.iter().map(|slot| json!({"slot": slot.to_string()})).collect::<Vec<_>>(),
            "signed_attestations": entry.attestations.iter().map(|(source, target)| json!({
                "source_epoch": source.to_string(), "target_epoch": target.to_string()
            })).collect::<Vec<_>>()
        })
    }).collect();
    json!({"metadata": {"interchange_format_version": "5", "genesis_validators_root": hex_byte_repeated(root, 32)}, "data": data}).to_string()
}

fn open(dir: &std::path::Path, mode: u8) -> SlashingProtection {
    match mode % 3 {
        0 => SlashingProtection::open(dir, ROOT, &[], false).expect("open"),
        1 => {
            let lock = SlashingProtection::lock(dir).expect("lock");
            SlashingProtection::open_locked(lock, dir, ROOT, &[], false).expect("open_locked")
        }
        _ => SlashingProtection::open_offline(dir, None).expect("open_offline"),
    }
}

fn reopen(record: SlashingProtection, dir: &std::path::Path, mode: u8) -> SlashingProtection {
    let path = record.path().expect("file-backed record").to_path_buf();
    let before = std::fs::read(&path).expect("read durable record");
    match mode {
        0..=2 => {
            drop(record);
            open(dir, mode)
        }
        3 => {
            drop(record);
            assert!(
                SlashingProtection::open(dir, Root::ZERO, &[], false).is_err(),
                "another genesis root must be refused"
            );
            assert_eq!(
                before,
                std::fs::read(&path).unwrap(),
                "failed open changed file"
            );
            open(dir, 0)
        }
        4 => {
            drop(record);
            assert!(
                SlashingProtection::open(dir, ROOT, &[key(MAX_KEY + 1)], false).is_err(),
                "unrecorded startup key must be refused"
            );
            assert_eq!(
                before,
                std::fs::read(&path).unwrap(),
                "failed open changed file"
            );
            open(dir, 1)
        }
        5 => {
            let empty = tempfile::tempdir().expect("temp dir");
            assert!(
                SlashingProtection::open_offline(empty.path(), None).is_err(),
                "offline open needs a record or chain root"
            );
            record
        }
        6 => {
            assert!(
                SlashingProtection::open(dir, ROOT, &[], false).is_err(),
                "second opener must be refused while lock is held"
            );
            record
        }
        7 => {
            drop(record);
            std::fs::write(&path, b"{\"metadata\":").expect("damage record");
            assert!(
                SlashingProtection::open(dir, ROOT, &[], false).is_err(),
                "damaged record must fail closed"
            );
            std::fs::write(&path, before).expect("restore record fixture");
            open(dir, 2)
        }
        8 => {
            drop(record);
            SlashingProtection::open(dir, ROOT, &[key(MAX_KEY)], true).expect("init missing key")
        }
        9 => {
            let empty = tempfile::tempdir().expect("temp dir");
            let mut offline =
                SlashingProtection::open_offline(empty.path(), Some(ROOT)).expect("offline create");
            assert!(
                offline.path().is_some_and(|path| !path.exists()),
                "offline open should not write before the first change"
            );
            offline
                .register(&[key(MAX_KEY)])
                .expect("offline first write");
            record
        }
        10 => {
            drop(record);
            let backup = dir.join("slashing_protection.backup");
            std::fs::rename(&path, &backup).expect("save record");
            std::fs::create_dir(&path).expect("put directory at record path");
            assert!(
                SlashingProtection::open(dir, ROOT, &[], false).is_err(),
                "non-file record must fail closed"
            );
            std::fs::remove_dir(&path).expect("remove test directory");
            std::fs::rename(&backup, &path).expect("restore record fixture");
            assert_eq!(before, std::fs::read(&path).unwrap());
            open(dir, 0)
        }
        11 | 12 => {
            drop(record);
            let bad = if mode == 11 {
                interchange(&[], false).replace("\"5\"", "\"4\"")
            } else {
                interchange(
                    &[ImportEntry {
                        key: 0,
                        blocks: vec![],
                        attestations: vec![(5, 5)],
                    }],
                    false,
                )
            };
            std::fs::write(&path, bad).expect("put invalid interchange at record path");
            assert!(
                SlashingProtection::open(dir, ROOT, &[], false).is_err(),
                "invalid durable record must fail closed"
            );
            std::fs::write(&path, before).expect("restore record fixture");
            open(dir, 1)
        }
        _ => unreachable!("generator bounds modes"),
    }
}

fn apply_op(record: &mut SlashingProtection, model: &mut Model, op: &Op, stats: &mut Stats) {
    match op {
        Op::Register(keys) => {
            let fresh = keys
                .iter()
                .copied()
                .filter(|key| !model.keys.contains_key(key))
                .collect::<BTreeSet<_>>()
                .len();
            let actual: Vec<_> = keys.iter().copied().map(key).collect();
            let n = record.register(&actual).expect("register");
            assert_eq!(n, fresh, "registration count was wrong: {op:?}");
            for &k in keys {
                model.register(k);
            }
        }
        Op::Block { key: k, slot, root } => {
            let slashable = model.block_slashable(*k, *slot, *root);
            let verdict = record
                .check_and_record_block(&key(*k), *slot)
                .expect("record block");
            if verdict.is_ok() {
                assert!(!slashable, "accepted slashable block: {op:?}");
                model.register(*k);
                model
                    .keys
                    .get_mut(k)
                    .unwrap()
                    .blocks
                    .push((*slot, Some(*root)));
                stats.accepted_blocks += 1;
            } else if !slashable && model.keys.contains_key(k) {
                stats.over_refused_blocks += 1;
            }
        }
        Op::Attest {
            keys,
            source,
            target,
            slot,
            root,
        } => {
            let vote = Vote {
                source: *source,
                target: *target,
                slot: *slot,
                root: Some(*root),
            };
            let public_keys: Vec<_> = keys.iter().copied().map(key).collect();
            let verdicts = record
                .check_and_record_attestations(&public_keys, &data(vote))
                .expect("record attestations");
            assert_eq!(verdicts.len(), keys.len());
            if !valid_vote(*source, *target) {
                assert!(
                    verdicts.iter().all(Result::is_err),
                    "accepted an impossible source/target pair: {op:?}"
                );
                return;
            }
            for (&k, verdict) in keys.iter().zip(verdicts) {
                let slashable = model.vote_slashable(k, vote);
                if verdict.is_ok() {
                    assert!(!slashable, "accepted slashable attestation: {op:?}");
                    model.register(k);
                    model.keys.get_mut(&k).unwrap().attestations.push(vote);
                    stats.accepted_attestations += 1;
                } else if !slashable && model.keys.contains_key(&k) && valid_vote(*source, *target)
                {
                    stats.over_refused_attestations += 1;
                }
            }
        }
        Op::Import {
            entries,
            wrong_chain,
        } => {
            let before = record.export(&all_keys()).expect("export before import");
            let result = record.import(&interchange(entries, *wrong_chain));
            if *wrong_chain {
                assert!(result.is_err(), "accepted another chain's interchange");
                assert_eq!(
                    before,
                    record.export(&all_keys()).unwrap(),
                    "rejected import changed record"
                );
            } else {
                let named = entries
                    .iter()
                    .map(|entry| entry.key)
                    .collect::<BTreeSet<_>>()
                    .len();
                assert_eq!(
                    result.expect("valid interchange must import"),
                    named,
                    "import named-count was wrong: {op:?}"
                );
                model.import(entries);
                stats.imports += 1;
            }
        }
        Op::Absorb {
            entries,
            register,
            wrong_chain,
        } => {
            let before = record.export(&all_keys()).expect("export before absorb");
            let before_file =
                std::fs::read(record.path().expect("file-backed")).expect("read before absorb");
            let staged = SlashingProtection::stage(&interchange(entries, *wrong_chain))
                .expect("stage valid interchange");
            let keys: Vec<_> = register.iter().copied().map(key).collect();
            let result = record.absorb(Some(&staged), &keys);
            if *wrong_chain {
                assert!(result.is_err(), "absorbed another chain's interchange");
                assert_eq!(
                    before,
                    record.export(&all_keys()).unwrap(),
                    "rejected absorb changed record"
                );
                assert_eq!(
                    before_file,
                    std::fs::read(record.path().unwrap()).unwrap(),
                    "rejected absorb changed durable file"
                );
            } else {
                let named_keys: BTreeSet<u8> = entries.iter().map(|entry| entry.key).collect();
                let new_keys: BTreeSet<u8> = register
                    .iter()
                    .copied()
                    .filter(|key| !named_keys.contains(key) && !model.keys.contains_key(key))
                    .collect();
                let absorbed = result.expect("valid staged history must absorb");
                assert_eq!(
                    absorbed.named,
                    named_keys.len(),
                    "absorb named-count was wrong: {op:?}"
                );
                assert_eq!(
                    absorbed.registered,
                    new_keys.len(),
                    "absorb registration count was wrong: {op:?}"
                );
                model.import(entries);
                for &key in register {
                    model.register(key);
                }
                stats.imports += 1;
            }
        }
        Op::Export(keys) => {
            let requested: Vec<_> = keys.iter().copied().map(key).collect();
            let text = record.export(&requested).expect("export");
            let parsed: Value = serde_json::from_str(&text).expect("export is JSON");
            assert_eq!(parsed["metadata"]["interchange_format_version"], "5");
        }
        Op::Reopen { .. } => unreachable!("handled by trace runner"),
    }
}

fn all_keys() -> Vec<BlsPubkey> {
    (0..=MAX_KEY).map(key).collect()
}

#[derive(Clone, Copy, Default)]
struct Watermarks {
    slot: Option<u64>,
    source: Option<u64>,
    target: Option<u64>,
}

fn decimal(value: &Value) -> u64 {
    value
        .as_str()
        .and_then(|text| text.parse().ok())
        .or_else(|| value.as_u64())
        .expect("record writes a decimal u64")
}

/// Read the documented EIP-3076 minimal bounds from the durable file without
/// using the production export or import code being checked by round trip.
fn durable_watermarks(record: &SlashingProtection) -> BTreeMap<u8, Watermarks> {
    let path = record.path().expect("file-backed record");
    let text = std::fs::read_to_string(path).expect("read durable record");
    let file: Value = serde_json::from_str(&text).expect("durable record JSON");
    let mut bounds = BTreeMap::new();
    for entry in file["data"].as_array().expect("record entries") {
        let pubkey = entry["pubkey"].as_str().expect("pubkey hex");
        let Some(k) = (0..=MAX_KEY).find(|k| pubkey == hex_byte_repeated(*k, 48)) else {
            continue;
        };
        let mut watermarks = Watermarks::default();
        for block in entry["signed_blocks"].as_array().expect("blocks") {
            watermarks.slot = watermarks.slot.max(Some(decimal(&block["slot"])));
        }
        for attestation in entry["signed_attestations"]
            .as_array()
            .expect("attestations")
        {
            watermarks.source = watermarks
                .source
                .max(Some(decimal(&attestation["source_epoch"])));
            watermarks.target = watermarks
                .target
                .max(Some(decimal(&attestation["target_epoch"])));
        }
        assert!(
            bounds.insert(k, watermarks).is_none(),
            "duplicate key in durable record"
        );
    }
    bounds
}

fn assert_model_safety(record: &mut SlashingProtection, model: &Model) {
    for &k in model.keys.keys() {
        assert!(
            record.contains(&key(k)),
            "registered or imported key {k} is absent"
        );
        for slot in 0..=MAX_SLOT {
            for root in 0..=1 {
                if model.block_slashable(k, slot, root) {
                    assert!(
                        record.check_block(&key(k), slot).is_err(),
                        "model-slashable block passed check_block: key {k}, slot {slot}, root {root}"
                    );
                    assert!(
                        record
                            .check_and_record_block(&key(k), slot)
                            .expect("block probe")
                            .is_err(),
                        "model-slashable block was recorded: key {k}, slot {slot}, root {root}"
                    );
                }
            }
        }
        for target in 0..=MAX_EPOCH {
            for source in 0..=target {
                if !valid_vote(source, target) {
                    continue;
                }
                for root in 0..=1 {
                    for slot_offset in 0..=1 {
                        let vote = Vote {
                            source,
                            target,
                            slot: target * 32 + slot_offset,
                            root: Some(root),
                        };
                        if model.vote_slashable(k, vote) {
                            let verdict = record
                                .check_and_record_attestations(&[key(k)], &data(vote))
                                .expect("safety probe must not need a write");
                            assert!(
                                verdict[0].is_err(),
                                "model-slashable attestation accepted: key {k}, {source}->{target}, root {root}, offset {slot_offset}"
                            );
                        }
                    }
                }
            }
        }
    }
}

pub fn run_safety(trace: &Trace) -> Stats {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut record = open(dir.path(), 0);
    let mut model = Model::default();
    let mut stats = Stats::default();
    for op in &trace.ops {
        if let Op::Reopen { mode } = op {
            record = reopen(record, dir.path(), *mode);
            if *mode == 8 {
                model.register(MAX_KEY);
            }
            stats.reopens += 1;
        } else {
            apply_op(&mut record, &mut model, op, &mut stats);
        }
        assert_model_safety(&mut record, &model);
    }
    stats
}

fn refusal_grid(record: &mut SlashingProtection) -> Vec<bool> {
    let selected = all_keys();
    let bounds = durable_watermarks(record);
    let text = record.export(&selected).expect("export for probing");
    // The test-only in-memory handle uses genesis root zero. Root does not
    // affect the refusal rules; change only the interchange envelope for it.
    let mut snapshot: Value = serde_json::from_str(&text).expect("snapshot JSON");
    snapshot["metadata"]["genesis_validators_root"] = json!(hex_byte_repeated(0, 32));
    let text = snapshot.to_string();
    let mut out = Vec::new();
    for k in 0..=MAX_KEY {
        for slot in 0..=MAX_SLOT {
            let minimum = bounds
                .get(&k)
                .is_none_or(|marks| marks.slot.is_some_and(|old| slot <= old));
            let observed = record.check_block(&key(k), slot).is_err();
            assert!(
                !minimum || observed,
                "durable block bound was not enforced for key {k}, slot {slot}"
            );
            out.push(minimum || observed);
        }
        for target in 0..=MAX_EPOCH {
            for source in 0..=target {
                if !valid_vote(source, target) {
                    continue;
                }
                for root in 0..=1 {
                    for slot_offset in 0..=1 {
                        if !record.contains(&key(k)) {
                            out.push(true);
                            continue;
                        }
                        let clone = SlashingProtection::in_memory();
                        let mut clone = clone.lock().expect("memory lock");
                        clone.import(&text).expect("import snapshot");
                        let vote = Vote {
                            source,
                            target,
                            slot: target * 32 + slot_offset,
                            root: Some(root),
                        };
                        let minimum = bounds.get(&k).is_none_or(|marks| {
                            marks.target.is_some_and(|old| target <= old)
                                || marks.source.is_some_and(|old| source < old)
                        });
                        if minimum {
                            // Refused queries cannot alter the live record.
                            // This also checks the direct API against the file.
                            assert!(
                                record
                                    .check_and_record_attestations(&[key(k)], &data(vote))
                                    .expect("durable lower-bound probe")[0]
                                    .is_err(),
                                "durable attestation bound was not enforced for key {k}, {source}->{target}"
                            );
                        }
                        let observed = clone
                            .check_and_record_attestations(&[key(k)], &data(vote))
                            .expect("probe memory record")[0]
                            .is_err();
                        out.push(minimum || observed);
                    }
                }
            }
        }
    }
    out
}

pub fn run_persistence(trace: &Trace) {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut record = open(dir.path(), 0);
    let mut model = Model::default();
    let mut stats = Stats::default();
    for op in &trace.ops {
        if let Op::Reopen { mode } = op {
            // Mode 8 explicitly initializes a new key; registration is a
            // state change, so compare refusals only for pure reopens.
            let before = (*mode != 8).then(|| refusal_grid(&mut record));
            record = reopen(record, dir.path(), *mode);
            if *mode == 8 {
                model.register(MAX_KEY);
            }
            if let Some(before) = before {
                let after = refusal_grid(&mut record);
                assert!(
                    before
                        .iter()
                        .zip(after.iter())
                        .all(|(old, new)| !*old || *new),
                    "reopen lost a refusal after {op:?}"
                );
            }
        } else {
            apply_op(&mut record, &mut model, op, &mut stats);
        }
    }
    let before = refusal_grid(&mut record);
    drop(record);
    let mut reopened = open(dir.path(), 1);
    let after = refusal_grid(&mut reopened);
    assert!(
        before
            .iter()
            .zip(after.iter())
            .all(|(old, new)| !*old || *new),
        "final reopen lost a refusal"
    );
}

pub fn run_roundtrip(trace: &Trace) {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut record = open(dir.path(), 0);
    let mut model = Model::default();
    let mut stats = Stats::default();
    for op in &trace.ops {
        if let Op::Reopen { mode } = op {
            record = reopen(record, dir.path(), *mode);
            if *mode == 8 {
                model.register(MAX_KEY);
            }
        } else {
            apply_op(&mut record, &mut model, op, &mut stats);
        }
    }
    let before = refusal_grid(&mut record);
    let exported = record.export(&all_keys()).expect("export");
    let fresh_dir = tempfile::tempdir().expect("temp dir");
    let mut fresh = open(fresh_dir.path(), 0);
    fresh.import(&exported).expect("round-trip import");
    let after = refusal_grid(&mut fresh);
    assert!(
        before
            .iter()
            .zip(after.iter())
            .all(|(old, new)| !*old || *new),
        "round trip lost a refusal"
    );
}

pub fn run_untrusted(text: &str) {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut record = open(dir.path(), 0);
    record.register(&[key(1)]).expect("register");
    record
        .check_and_record_block(&key(1), 3)
        .expect("record block")
        .expect("sign");
    let before = record.export(&all_keys()).expect("export before");
    let before_file = std::fs::read(record.path().expect("file-backed")).expect("read before");
    let _ = SlashingProtection::stage(text);
    let imported = record.import(text);
    if imported.is_err() {
        assert_eq!(
            before,
            record.export(&all_keys()).expect("export after"),
            "rejected import changed record"
        );
        assert_eq!(
            before_file,
            std::fs::read(record.path().unwrap()).expect("read after"),
            "rejected import changed durable file"
        );
    }
}
