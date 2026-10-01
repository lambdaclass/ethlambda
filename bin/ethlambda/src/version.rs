/// The leanVM revision the binary was built against, resolved from `Cargo.lock`
/// by `build.rs`.
///
/// leanVM owns the whole signature stack, so this identifies the XMSS scheme
/// this build signs, verifies and generates keys for. Worth recording next to
/// anything that outlives the process, since the scheme's own parameters have
/// survived a change of hash function unchanged and so cannot stand in for it.
pub const LEANVM_REV: &str = env!("ETHLAMBDA_LEANVM_REV");

/// Client version string with git info.
/// Format: ethlambda/v0.1.0-main-892ad575.../x86_64-unknown-linux-gnu/rustc-v1.85.0
pub const CLIENT_VERSION: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/v",
    env!("CARGO_PKG_VERSION"),
    "-",
    env!("VERGEN_GIT_BRANCH"),
    "-",
    env!("VERGEN_GIT_SHA"),
    "/",
    env!("VERGEN_RUSTC_HOST_TRIPLE"),
    "/rustc-v",
    env!("VERGEN_RUSTC_SEMVER")
);
