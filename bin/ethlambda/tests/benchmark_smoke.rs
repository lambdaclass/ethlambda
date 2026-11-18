//! Smoke test for the block-building benchmark and its JSON report contract.
//!
//! This was a CI job of its own (`cargo run ... benchmark synthetic | jq -e`),
//! which compiled the whole node a second time for a run that takes seconds.
//! As an integration test it rides in the workspace test build instead: cargo
//! builds the binary for it (`CARGO_BIN_EXE_ethlambda`), and the run happens in
//! a process of its own, so the benchmark's phase timers read the global
//! metrics registry without any other test observing the same histograms.
//!
//! No fixtures: with `--mock-crypto` the synthetic workload generates its own
//! chain and reads no files.

use std::fs::{self, File};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// How long the run may take before it is killed and the test fails. It takes
/// about a second in a `release-fast` build, so this is generous; the point is
/// that a hung benchmark fails here instead of holding `Test (node)` until the
/// job's own timeout.
const DEADLINE: Duration = Duration::from_secs(120);

#[test]
fn synthetic_benchmark_prints_a_schema_1_json_report() {
    // Output goes to files rather than pipes, so the benchmark can never block
    // on a full pipe while this thread is only polling it.
    let dir = tempfile::tempdir().expect("creates a temporary directory");
    let stdout_path = dir.path().join("stdout");
    let stderr_path = dir.path().join("stderr");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ethlambda"))
        .args([
            "benchmark",
            "synthetic",
            "--mock-crypto",
            "--num-validators",
            "4",
            "--warmup-slots",
            "4",
            "--iterations",
            "3",
            "--format",
            "json",
        ])
        .stdin(Stdio::null())
        .stdout(File::create(&stdout_path).expect("creates the stdout file"))
        .stderr(File::create(&stderr_path).expect("creates the stderr file"))
        .spawn()
        .expect("the ethlambda binary starts");

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("polls the benchmark") {
            break status;
        }
        if started.elapsed() > DEADLINE {
            // Best effort: the process may have exited between the two calls.
            let _ = child.kill();
            let _ = child.wait();
            let stderr = fs::read_to_string(&stderr_path).unwrap_or_default();
            panic!("benchmark still running after {DEADLINE:?}, killed it; stderr:\n{stderr}");
        }
        thread::sleep(Duration::from_millis(50));
    };

    let stderr = fs::read_to_string(&stderr_path).unwrap_or_default();
    assert!(
        status.success(),
        "benchmark exited with {status}; stderr:\n{stderr}"
    );

    // Logs go to stderr, so stdout is the report and nothing else.
    let stdout = fs::read(&stdout_path).expect("reads the stdout file");
    let report: serde_json::Value = serde_json::from_slice(&stdout)
        .unwrap_or_else(|err| panic!("stdout is not one JSON document ({err}); stderr:\n{stderr}"));
    assert_eq!(
        report["schema_version"], 1,
        "a schema change has to be deliberate: bump it and update the consumers"
    );
    let samples = report["samples"]
        .as_array()
        .expect("the report carries a `samples` array");
    assert_eq!(samples.len(), 3, "one sample per measured iteration");
}
