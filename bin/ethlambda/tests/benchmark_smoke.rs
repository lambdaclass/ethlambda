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

use std::process::Command;

#[test]
fn synthetic_benchmark_prints_a_schema_1_json_report() {
    let output = Command::new(env!("CARGO_BIN_EXE_ethlambda"))
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
        .output()
        .expect("the ethlambda binary runs");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "benchmark exited with {}; stderr:\n{stderr}",
        output.status
    );

    // Logs go to stderr, so stdout is the report and nothing else.
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
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
