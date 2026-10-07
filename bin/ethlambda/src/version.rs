use std::sync::LazyLock;

/// The leanVM revision the binary was built against, resolved from `Cargo.lock`
/// by `build.rs`.
///
/// leanVM owns the whole signature stack, so this identifies the XMSS scheme
/// this build signs, verifies and generates keys for. Worth recording next to
/// anything that outlives the process, since the scheme's own parameters have
/// survived a change of hash function unchanged and so cannot stand in for it.
pub const LEANVM_REV: &str = env!("ETHLAMBDA_LEANVM_REV");

/// Environment variable that overrides the release channel baked at build time.
///
/// Promoting a release candidate stamps `ETHLAMBDA_CHANNEL=stable` onto the
/// image config instead of rebuilding (see `.github/workflows/release_promote.yaml`),
/// so the binary that ships is byte-for-byte the one tested as the candidate,
/// yet reports itself as stable rather than as `rc.N`.
const CHANNEL_ENV: &str = "ETHLAMBDA_CHANNEL";

/// Channel baked at build time: the git branch, or the `rc.N` suffix of a
/// release-candidate tag (CI sets `VERGEN_GIT_BRANCH` for tag builds, since a
/// tag checkout has no branch for vergen to read).
const BUILD_CHANNEL: &str = env!("VERGEN_GIT_BRANCH");

/// Client version string with git info.
/// Format: ethlambda/v0.1.0-main-892ad575.../x86_64-unknown-linux-gnu/rustc-v1.85.0
///
/// The channel segment (`main` above) is resolved once, at first use, so
/// `ETHLAMBDA_CHANNEL` can replace it without a rebuild.
pub fn client_version() -> &'static str {
    static CLIENT_VERSION: LazyLock<String> = LazyLock::new(|| {
        let channel_override = std::env::var(CHANNEL_ENV).ok();
        let channel = resolve_channel(channel_override.as_deref(), BUILD_CHANNEL);
        format!(
            "{}/v{}-{}-{}/{}/rustc-v{}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            channel,
            env!("VERGEN_GIT_SHA"),
            env!("VERGEN_RUSTC_HOST_TRIPLE"),
            env!("VERGEN_RUSTC_SEMVER"),
        )
    });
    &CLIENT_VERSION
}

/// An empty override counts as unset, so `ETHLAMBDA_CHANNEL=` in a compose file
/// or `docker run -e` cannot blank the channel out of the version string.
fn resolve_channel<'a>(channel_override: Option<&'a str>, build_channel: &'a str) -> &'a str {
    channel_override
        .filter(|channel| !channel.is_empty())
        .unwrap_or(build_channel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_replaces_the_build_channel() {
        assert_eq!(resolve_channel(Some("stable"), "rc.1"), "stable");
    }

    #[test]
    fn unset_or_empty_override_keeps_the_build_channel() {
        assert_eq!(resolve_channel(None, "rc.1"), "rc.1");
        assert_eq!(resolve_channel(Some(""), "rc.1"), "rc.1");
    }
}
