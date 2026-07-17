//! Protocol constants shared across crates.

/// Fork digest embedded in every gossipsub topic string, as lowercase hex
/// without a `0x` prefix.
///
/// The [leanSpec](https://github.com/leanEthereum/leanSpec/pull/622)
/// currently mandates a dummy value shared across all clients; this will
/// eventually be derived from the fork version and genesis validators root.
// TODO: derive dynamically once the spec defines fork identification.
pub const FORK_DIGEST: &str = "12345678";
