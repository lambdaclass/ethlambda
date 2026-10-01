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
        // handshake never identifies anything. `get` rather than a slice or
        // `take(8)`, since `VERGEN_GIT_SHA` is not guaranteed to be eight or
        // more characters in every build configuration.
        commit: format!(
            "0x{}",
            env!("VERGEN_GIT_SHA").get(..8).unwrap_or("00000000")
        ),
    }
}
