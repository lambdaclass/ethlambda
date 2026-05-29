use std::{env, fs, path::PathBuf};

use vergen_git2::{Emitter, Git2Builder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Embed the build's short git SHA (consumed via env!("VERGEN_GIT_SHA")) so
    // publish-side gossip diagnostics can report which client build emitted a
    // message. Mirrors bin/ethlambda/build.rs.
    let git2 = Git2Builder::default().sha(true).build()?;
    Emitter::default().add_instructions(&git2)?.emit()?;

    // Surface the resolved `snap` crate version so the same diagnostics can
    // record which snappy implementation produced the compressed payload. The
    // version is not available via any standard Cargo env var, so we read it
    // out of the workspace lockfile.
    let snap_version = snap_version().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=SNAP_VERSION={snap_version}");

    Ok(())
}

/// Parse the `snap` package version out of the workspace `Cargo.lock`.
///
/// Walks up from this crate's manifest dir until a `Cargo.lock` is found, then
/// scans for the `snap` package entry. Returns `None` if the lockfile or entry
/// is missing (the caller falls back to `"unknown"`).
fn snap_version() -> Option<String> {
    let mut dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").ok()?);
    let lockfile = loop {
        let candidate = dir.join("Cargo.lock");
        if candidate.is_file() {
            break candidate;
        }
        if !dir.pop() {
            return None;
        }
    };
    println!("cargo:rerun-if-changed={}", lockfile.display());

    let contents = fs::read_to_string(&lockfile).ok()?;
    let mut lines = contents.lines();
    while let Some(line) = lines.next() {
        if line.trim() != "name = \"snap\"" {
            continue;
        }
        // Within the same `[[package]]` block, find the version line.
        for next in lines.by_ref() {
            let next = next.trim();
            if next.starts_with("[[package]]") {
                break;
            }
            if let Some(version) = next.strip_prefix("version = \"") {
                return Some(version.trim_end_matches('"').to_string());
            }
        }
    }
    None
}
