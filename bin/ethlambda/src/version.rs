/// The leanVM revision the binary was built against, resolved from `Cargo.lock`
/// by `build.rs`.
///
/// leanVM owns the whole signature stack, so this identifies the XMSS scheme
/// this build signs, verifies and generates keys for. Worth recording next to
/// anything that outlives the process, since the scheme's own parameters have
/// survived a change of hash function unchanged and so cannot stand in for it.
pub const LEANVM_REV: &str = env!("ETHLAMBDA_LEANVM_REV");

use ethlambda_engine::types::ClientVersionV1;

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

/// This client's two-letter code, as the Engine API and block graffiti carry it.
///
/// `identification.md` reserves a code for each client it lists and leaves any
/// other client free to pick two letters that collide with none of them. None
/// is reserved for ethlambda, and `LA` collides with nothing listed.
pub const CLIENT_CODE: &str = "LA";

/// This build as `engine_getClientVersionV1` identifies it.
///
/// Built once and shared by the Engine API handshake and block production,
/// which reads its `code` and `commit` into the graffiti's version suffix, so
/// the execution client and the chain are told the same thing.
pub fn engine_client_version() -> ClientVersionV1 {
    ClientVersionV1 {
        code: CLIENT_CODE.to_string(),
        name: "ethlambda".to_string(),
        version: CLIENT_VERSION.to_string(),
        // `identification.md` types `commit` as DATA, 4 bytes, and geth
        // decodes it into `hexutil.Bytes`, which rejects a bare hex string with
        // "hex string without 0x prefix". So the prefix is not cosmetic: without
        // it `engine_getClientVersionV1` comes back an RPC error and the
        // handshake never identifies anything. The hash is `build.rs`'s full
        // one, not `VERGEN_GIT_SHA`, which is abbreviated to seven digits.
        // `get` rather than a slice, since a build with no git checkout has
        // an empty hash.
        commit: format!(
            "0x{}",
            env!("ETHLAMBDA_GIT_COMMIT").get(..8).unwrap_or("00000000")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Engine API's commit is this build's own rather than the all-zero
    /// fallback. `VERGEN_GIT_SHA` abbreviates the same hash, so the two agree
    /// on every digit they share.
    #[test]
    fn the_engine_commit_is_this_builds_commit() {
        let abbreviated = env!("VERGEN_GIT_SHA");
        // With no checkout to read, vergen reports a placeholder instead of a
        // hash, and there is no commit to compare against.
        if !abbreviated.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return;
        }
        let commit = engine_client_version().commit;
        let digits = commit
            .strip_prefix("0x")
            .expect("geth refuses a commit without the 0x prefix");
        assert_eq!(digits.len(), 8, "{commit} is not four bytes");
        let shared = abbreviated.len().min(digits.len());
        assert_eq!(&digits[..shared], &abbreviated[..shared]);
    }
}
