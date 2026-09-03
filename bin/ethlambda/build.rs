use std::path::PathBuf;

use vergen_git2::{Emitter, Git2Builder, RustcBuilder};

/// Crate name whose resolved git revision is embedded in the binary.
/// leanVM owns the whole crypto stack (it internalized XMSS), and every crate
/// ethlambda takes from it resolves to one revision, so this single pin
/// identifies the crypto the binary was built against.
const LEANVM_PACKAGE: &str = "lean-multisig";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let git2 = Git2Builder::default().branch(true).sha(true).build()?;
    let rustc = RustcBuilder::default()
        .semver(true)
        .host_triple(true)
        .build()?;

    Emitter::default()
        .add_instructions(&rustc)?
        .add_instructions(&git2)?
        .emit()?;

    emit_crypto_revs();

    Ok(())
}

/// Embed the resolved leanVM git revision from the workspace Cargo.lock.
///
/// leanVM is pinned to a rev upstream, so a `cargo update` or a rev bump
/// changes the measured crypto with little or no ethlambda diff; benchmark
/// reports embed the revision to keep results interpretable across lock bumps.
fn emit_crypto_revs() {
    let rev = lockfile_git_revs()
        .and_then(|revs| revs.get(LEANVM_PACKAGE).cloned())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=ETHLAMBDA_LEANVM_REV={rev}");
    if let Some(lockfile) = workspace_lockfile() {
        println!("cargo:rerun-if-changed={}", lockfile.display());
    }
}

fn workspace_lockfile() -> Option<PathBuf> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    Some(PathBuf::from(manifest_dir).join("../../Cargo.lock"))
}

/// Map each git-sourced package in the lockfile to its resolved revision.
///
/// Both fields of a `[[package]]` block are collected before the revision is
/// extracted, so the result does not depend on TOML field order within the
/// table (a lock-file reformatter emitting `source` before `name` would
/// otherwise silently yield "unknown").
fn lockfile_git_revs() -> Option<std::collections::HashMap<String, String>> {
    let lockfile = std::fs::read_to_string(workspace_lockfile()?).ok()?;
    let mut revs = std::collections::HashMap::new();
    // A lockfile is a flat sequence of `[[package]]` blocks; splitting on the
    // header gives one chunk per package (the first chunk is the file preamble,
    // which has no `name` and is skipped).
    for block in lockfile.split("[[package]]") {
        let mut name = None;
        let mut source = None;
        for line in block.lines() {
            let line = line.trim();
            if let Some(value) = line.strip_prefix("name = ") {
                name = Some(value.trim_matches('"').to_string());
            } else if let Some(value) = line.strip_prefix("source = ") {
                source = Some(value.trim_matches('"').to_string());
            }
        }
        // source = "git+https://github.com/leanEthereum/leanVM.git?rev=<rev>#<rev>"
        let (Some(name), Some(source)) = (name, source) else {
            continue;
        };
        if let Some(rev) = source.strip_prefix("git+").and_then(|s| s.rsplit_once('#')) {
            revs.insert(name, rev.1.to_string());
        }
    }
    Some(revs)
}
