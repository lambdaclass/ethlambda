#[path = "properties/generators.rs"]
mod generators;

use std::sync::atomic::{AtomicU64, Ordering};

use ephyra::{Config, check, check_shrinker};
use ephyra_validator::model::{
    DURABLE_CORRUPTIONS, DurableCase, check_durable_corruption, run_persistence, run_roundtrip,
    run_safety, run_untrusted,
};

fn config(name: &str, cases: u64) -> Config {
    Config::default().name(name).tests(cases)
}

#[test]
fn generator_and_shrinker_are_valid() {
    let cfg = config("trace_generator", 300);
    ephyra::check_generator(&cfg, generators::traces(), generators::valid_trace).assert_passed();
    check_shrinker(
        &cfg,
        generators::traces(),
        generators::valid_trace,
        |trace| trace.ops.len() as u64,
    )
    .assert_passed();
    ephyra::check_generator(&cfg, generators::texts(), generators::valid_text).assert_passed();
    check_shrinker(&cfg, generators::texts(), generators::valid_text, |text| {
        text.chars().count() as u64
    })
    .assert_passed();
    ephyra::check_generator(
        &cfg,
        generators::durable_cases(),
        generators::valid_durable_case,
    )
    .assert_passed();
    check_shrinker(
        &cfg,
        generators::durable_cases(),
        generators::valid_durable_case,
        |case| u64::from(case.slot) + u64::from(case.opener),
    )
    .assert_passed();
}

#[test]
fn model_safety() {
    static OVER_BLOCK: AtomicU64 = AtomicU64::new(0);
    static OVER_ATTEST: AtomicU64 = AtomicU64::new(0);
    static ACCEPT_BLOCK: AtomicU64 = AtomicU64::new(0);
    static ACCEPT_ATTEST: AtomicU64 = AtomicU64::new(0);
    let report = check(
        &config("model_safety", 200),
        generators::traces(),
        |trace| {
            let stats = run_safety(&trace);
            OVER_BLOCK.fetch_add(stats.over_refused_blocks, Ordering::Relaxed);
            OVER_ATTEST.fetch_add(stats.over_refused_attestations, Ordering::Relaxed);
            ACCEPT_BLOCK.fetch_add(stats.accepted_blocks, Ordering::Relaxed);
            ACCEPT_ATTEST.fetch_add(stats.accepted_attestations, Ordering::Relaxed);
        },
    );
    println!("{report}");
    println!(
        "over-refusal blocks={} attestations={}; accepted blocks={} attestations={}",
        OVER_BLOCK.load(Ordering::Relaxed),
        OVER_ATTEST.load(Ordering::Relaxed),
        ACCEPT_BLOCK.load(Ordering::Relaxed),
        ACCEPT_ATTEST.load(Ordering::Relaxed)
    );
    report.assert_passed();
}

#[test]
fn persistence() {
    let report = check(&config("persistence", 100), generators::traces(), |trace| {
        run_persistence(&trace)
    });
    println!("{report}");
    report.assert_passed();
}

#[test]
fn export_import_round_trip() {
    let report = check(&config("round_trip", 100), generators::traces(), |trace| {
        run_roundtrip(&trace)
    });
    println!("{report}");
    report.assert_passed();
}

#[test]
fn untrusted_interchange() {
    let report = check(
        &config("untrusted_interchange", 300),
        generators::texts(),
        |text| run_untrusted(&text),
    );
    println!("{report}");
    report.assert_passed();
}

#[test]
fn malformed_durable_records() {
    // Every mutation and every public file-backed opening path is mandatory;
    // the generator adds varied slots and combinations.
    for corruption in DURABLE_CORRUPTIONS {
        for opener in 0..=2 {
            check_durable_corruption(&DurableCase {
                slot: 5,
                corruption,
                opener,
            });
        }
    }
    let report = check(
        &config("malformed_durable_records", 300),
        generators::durable_cases(),
        |case| check_durable_corruption(&case),
    );
    println!("{report}");
    report.assert_passed();
}

#[test]
fn missing_directory_lock_fails_closed() {
    use ethlambda_types::beacon::primitives::Root;
    use ethlambda_validator::slashing_protection::SlashingProtection;

    let dir = tempfile::tempdir().expect("temp dir");
    let absent = dir.path().join("absent");
    assert!(SlashingProtection::lock(&absent).is_err());
    assert!(SlashingProtection::open(&absent, Root::ZERO, &[], false).is_err());
    assert!(!absent.exists(), "failed open created a directory");
}

#[cfg(unix)]
#[test]
fn failed_writes_fail_closed() {
    use std::os::unix::fs::PermissionsExt;

    use ethlambda_types::beacon::containers::shared::{AttestationData, Checkpoint};
    use ethlambda_types::beacon::primitives::{BlsPubkey, H256, Root};
    use ethlambda_validator::slashing_protection::SlashingProtection;

    let dir = tempfile::tempdir().expect("temp dir");
    let key = BlsPubkey([1; 48]);
    let mut record =
        SlashingProtection::open(dir.path(), H256([0x42; 32]), &[key], true).expect("open");
    let before = record.export(&[key]).expect("export");
    let data = AttestationData {
        slot: 128,
        index: 0,
        beacon_block_root: H256([2; 32]),
        source: Checkpoint {
            epoch: 3,
            root: Root::ZERO,
        },
        target: Checkpoint {
            epoch: 4,
            root: Root::ZERO,
        },
    };
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500))
        .expect("make directory read only");
    let block = record.check_and_record_block(&key, 4);
    let attest = record.check_and_record_attestations(&[key], &data);
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("restore directory permissions");

    if block.is_ok() || attest.is_ok() {
        eprintln!("skipped: directory permissions did not inject write failures");
        return;
    }
    assert_eq!(
        before,
        record.export(&[key]).expect("export after failed writes")
    );
    record
        .check_and_record_block(&key, 4)
        .expect("retry writes")
        .expect("block signs");
    record
        .check_and_record_attestations(&[key], &data)
        .expect("retry writes")[0]
        .expect("attestation signs");
}

#[cfg(target_os = "macos")]
#[test]
fn post_rename_directory_flush_failure() {
    use std::process::Command;

    let dir = tempfile::tempdir().expect("fault fixture directory");
    let library = dir.path().join("directory_flush.dylib");
    let source = concat!(env!("CARGO_MANIFEST_DIR"), "/faults/directory_flush.c");
    let build = Command::new("cc")
        .args(["-dynamiclib", "-O2", "-o"])
        .arg(&library)
        .arg(source)
        .output()
        .expect("compile macOS fault injector");
    assert!(
        build.status.success(),
        "C compiler: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let child = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "post_rename_directory_flush_child",
            "--nocapture",
        ])
        .env("DYLD_INSERT_LIBRARIES", &library)
        .env("EPHYRA_RUN_FAULT_CHILD", "1")
        .env(
            "EPHYRA_FAIL_DIRECTORY_FLUSH",
            dir.path()
                .canonicalize()
                .expect("canonical fault directory"),
        )
        .output()
        .expect("run injected test child");
    let output = format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(
        child.status.success(),
        "injected child {:?} failed: {output}",
        child.status
    );
    assert!(
        output.contains("1 passed"),
        "injected child did not run: {output}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn post_rename_directory_flush_child() {
    use ethlambda_types::beacon::containers::shared::{AttestationData, Checkpoint};
    use ethlambda_types::beacon::primitives::{BlsPubkey, H256, Root};
    use ethlambda_validator::error::Error;
    use ethlambda_validator::slashing_protection::SlashingProtection;

    if std::env::var_os("EPHYRA_RUN_FAULT_CHILD").is_none() {
        return;
    }
    let dir = std::env::var_os("EPHYRA_FAIL_DIRECTORY_FLUSH").expect("fault directory");
    let dir = std::path::PathBuf::from(dir);
    let key = BlsPubkey([1; 48]);
    let mut record = SlashingProtection::open(&dir, H256([0x42; 32]), &[key], true)
        .expect("open before fault is active");
    let path = record.path().expect("durable record").to_path_buf();
    let marker = dir.join(".ephyra_fault_active");
    std::fs::write(&marker, []).expect("activate fault");

    let block = record.check_and_record_block(&key, 5);
    assert!(
        matches!(block, Err(Error::Unflushed { .. })),
        "block: {block:?}"
    );
    assert!(
        record.check_block(&key, 5).is_err(),
        "memory lost unflushed slot"
    );
    let disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read renamed record"))
            .expect("renamed record JSON");
    assert_eq!(disk["data"][0]["signed_blocks"][0]["slot"], "5");

    let data = AttestationData {
        slot: 128,
        index: 0,
        beacon_block_root: Root::repeat_byte(2),
        source: Checkpoint {
            epoch: 3,
            root: Root::ZERO,
        },
        target: Checkpoint {
            epoch: 4,
            root: Root::ZERO,
        },
    };
    let attest = record.check_and_record_attestations(&[key], &data);
    assert!(
        matches!(attest, Err(Error::Unflushed { .. })),
        "attestation: {attest:?}"
    );
    let retry = record
        .check_and_record_attestations(&[key], &data)
        .expect("retry is a refusal, not another write");
    assert!(retry[0].is_err(), "memory lost unflushed vote");

    std::fs::remove_file(&marker).expect("deactivate fault");
    drop(record);
    let mut recovered = SlashingProtection::open(&dir, H256([0x42; 32]), &[key], false)
        .expect("reopen after fault");
    assert!(
        recovered.check_block(&key, 5).is_err(),
        "disk lost unflushed slot"
    );
    assert!(
        recovered
            .check_and_record_attestations(&[key], &data)
            .unwrap()[0]
            .is_err(),
        "disk lost unflushed vote"
    );
    recovered
        .check_and_record_block(&key, 6)
        .expect("write after recovery")
        .expect("next slot is allowed");
}
