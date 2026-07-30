use std::path::PathBuf;

use vergen_git2::{Emitter, Git2Builder, RustcBuilder};

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

    emit_leansig_rev();

    Ok(())
}

/// Embed the resolved leansig git revision from the workspace Cargo.lock.
///
/// leansig is pinned to a moving branch, so a `cargo update` changes the
/// measured crypto with zero ethlambda diff; benchmark reports embed this
/// revision to keep results interpretable across lock bumps.
fn emit_leansig_rev() {
    let rev = leansig_rev_from_lockfile().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=ETHLAMBDA_LEANSIG_REV={rev}");
    if let Some(lockfile) = workspace_lockfile() {
        println!("cargo:rerun-if-changed={}", lockfile.display());
    }
}

fn workspace_lockfile() -> Option<PathBuf> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    Some(PathBuf::from(manifest_dir).join("../../Cargo.lock"))
}

fn leansig_rev_from_lockfile() -> Option<String> {
    let lockfile = std::fs::read_to_string(workspace_lockfile()?).ok()?;
    let mut in_leansig_package = false;
    for line in lockfile.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            in_leansig_package = false;
        } else if line == "name = \"leansig\"" {
            in_leansig_package = true;
        } else if in_leansig_package {
            // source = "git+https://github.com/leanEthereum/leanSig?branch=devnet4#<rev>"
            if let Some(source) = line.strip_prefix("source = ") {
                let rev = source.trim_matches('"').rsplit('#').next()?;
                return Some(rev.to_string());
            }
        }
    }
    None
}
