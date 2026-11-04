//! The client-version suffix block production appends to a proposer's graffiti.
//!
//! The proposer's own text comes first, as sent by the validator client, then
//! as much of `<EL code><EL commit><CL code><CL commit>` as the remaining room
//! allows, for example `hello RH1a2bLA3c4d`. The codes and the four-byte commits
//! are the fields `engine_getClientVersionV1` exists to carry "within a limited
//! space (e.g. in block `graffiti`)", in `identification.md`'s own words, and
//! the layout is the one Lighthouse, Teku, Prysm, Lodestar and Grandine share,
//! so tools that measure client diversity from graffiti read these blocks too.
//!
//! # There is no opt-out
//!
//! The suffix is appended to every block this node produces, whatever the
//! validator client asked for, including Lighthouse's `graffiti_policy` query
//! parameter, which is not read. Consensus never reads graffiti, so the only
//! thing the suffix changes is what the chain says about who built the block.
//!
//! # Tiers
//!
//! The suffix shrinks rather than cutting the proposer's text short. With `n`
//! bytes of proposer text, one more for the separating space when `n > 0`:
//!
//! | `n` | Appended |
//! |---|---|
//! | 0 | `RH1a2bLA3c4d`, with no space |
//! | 1-19 | ` RH1a2bLA3c4d` |
//! | 20-23 | ` RH1aLA3c` |
//! | 24-27 | ` RHLA` |
//! | 28-29 | ` RH` |
//! | 30-32 | nothing |
//!
//! These are Lighthouse's tiers exactly, down to keeping the execution client's
//! code rather than this client's when only two bytes fit: the convention
//! (Teku's and Prysm's too) is that the last code standing is the execution
//! layer's.
//!
//! When the execution client's version cannot be had, the suffix is this
//! client's half alone: ` LA3c4d` up to 25 bytes of text, ` LA` up to 29. Here
//! Lighthouse differs, replacing the proposer's text with its own version
//! string; Teku, Prysm and Lodestar keep the text, and so does this.

use std::sync::Arc;
use std::time::Duration;

use ethlambda_engine::{EngineClient, types::ClientVersionV1};
use ethlambda_types::beacon::primitives::{Bytes32, H256};
use tracing::debug;

/// A block's graffiti field is exactly this wide.
const GRAFFITI_BYTES: usize = 32;

/// How long block production waits for the execution client's version.
///
/// The call runs alongside the payload build rather than before it, so a
/// healthy execution client costs the block nothing. The bound is for one that
/// does not answer: past it the block goes out with this client's half of the
/// suffix alone rather than later. Short because the question is trivial; an
/// execution client that takes longer than this to report its own version is
/// unlikely to have a payload ready either.
const EL_VERSION_TIMEOUT: Duration = Duration::from_millis(500);

/// This node's own version, as block production reads it off the router.
#[derive(Debug, Clone)]
pub(crate) struct OwnVersion(pub(crate) Arc<ClientVersionV1>);

/// A client's two-letter code and the first four hex digits of its commit: the
/// two things graffiti has room for.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientTag {
    code: String,
    commit: String,
}

impl ClientTag {
    /// `None` unless `code` is two ASCII letters and `commit` starts with at
    /// least four hex digits, `0x`-prefixed or not.
    ///
    /// Strict because the result is written into every block: a version that
    /// does not look like one is left out rather than copied onto the chain.
    fn parse(version: &ClientVersionV1) -> Option<Self> {
        let code = &version.code;
        if code.len() != 2 || !code.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            return None;
        }
        let commit = version
            .commit
            .strip_prefix("0x")
            .or_else(|| version.commit.strip_prefix("0X"))
            .unwrap_or(&version.commit);
        let commit = commit.get(..4)?;
        if !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        Some(Self {
            code: code.to_ascii_uppercase(),
            commit: commit.to_ascii_lowercase(),
        })
    }

    /// This node's own tag. Its commit falls back to `0000` rather than the
    /// tag being dropped, since a build without git metadata is still this
    /// client and still worth naming.
    fn own(version: &ClientVersionV1) -> Self {
        Self::parse(version).unwrap_or_else(|| Self {
            code: version.code.to_ascii_uppercase(),
            commit: "0000".to_string(),
        })
    }
}

/// The suffixes to try, longest first.
fn candidates(el: Option<&ClientTag>, cl: &ClientTag) -> Vec<String> {
    match el {
        Some(el) => vec![
            format!("{}{}{}{}", el.code, el.commit, cl.code, cl.commit),
            format!(
                "{}{}{}{}",
                el.code,
                &el.commit[..2],
                cl.code,
                &cl.commit[..2]
            ),
            format!("{}{}", el.code, cl.code),
            el.code.clone(),
        ],
        None => vec![format!("{}{}", cl.code, cl.commit), cl.code.clone()],
    }
}

/// `graffiti` with the longest version suffix that fits appended.
///
/// The proposer's text is everything before the trailing zero bytes, and is
/// never shortened: when not even the shortest suffix fits, the graffiti is
/// returned as it came. `el` is the execution client's version, `None` when it
/// could not be had; `cl` is this node's own.
pub(crate) fn with_client_versions(
    graffiti: Bytes32,
    el: Option<&ClientVersionV1>,
    cl: &ClientVersionV1,
) -> Bytes32 {
    let padding = graffiti
        .0
        .iter()
        .rev()
        .take_while(|byte| **byte == 0)
        .count();
    let text_len = GRAFFITI_BYTES - padding;
    let separator = usize::from(text_len > 0);

    let el = el.and_then(ClientTag::parse);
    let cl = ClientTag::own(cl);
    let Some(suffix) = candidates(el.as_ref(), &cl)
        .into_iter()
        .find(|suffix| text_len + separator + suffix.len() <= GRAFFITI_BYTES)
    else {
        return graffiti;
    };

    let mut bytes = [0u8; GRAFFITI_BYTES];
    bytes[..text_len].copy_from_slice(&graffiti.0[..text_len]);
    if separator == 1 {
        bytes[text_len] = b' ';
    }
    let start = text_len + separator;
    bytes[start..start + suffix.len()].copy_from_slice(suffix.as_bytes());
    H256(bytes)
}

/// The graffiti as text for a log line: the bytes before the trailing zeros,
/// with anything that is not UTF-8 replaced.
pub(crate) fn display(graffiti: &Bytes32) -> String {
    let padding = graffiti
        .0
        .iter()
        .rev()
        .take_while(|byte| **byte == 0)
        .count();
    String::from_utf8_lossy(&graffiti.0[..GRAFFITI_BYTES - padding]).into_owned()
}

/// The execution client's version, or `None` when it cannot be had in time.
///
/// Anything but exactly one entry is `None` too. `identification.md` has a
/// multiplexer answer one entry per execution client behind it, and a graffiti
/// has room to name one, which would then be a guess.
pub(crate) async fn execution_client_version(
    engine: &EngineClient,
    ours: &ClientVersionV1,
) -> Option<ClientVersionV1> {
    match tokio::time::timeout(EL_VERSION_TIMEOUT, engine.client_version(ours)).await {
        Ok(Ok(mut versions)) if versions.len() == 1 => versions.pop(),
        Ok(Ok(versions)) => {
            debug!(
                count = versions.len(),
                "The execution client reported other than one version; graffiti names this client only"
            );
            None
        }
        Ok(Err(err)) => {
            debug!(%err, "The execution client did not report its version; graffiti names this client only");
            None
        }
        Err(_) => {
            debug!(
                "The execution client's version did not arrive in time; graffiti names this client only"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(code: &str, commit: &str) -> ClientVersionV1 {
        ClientVersionV1 {
            code: code.to_string(),
            name: "test".to_string(),
            version: "v0.0.0".to_string(),
            commit: commit.to_string(),
        }
    }

    fn reth() -> ClientVersionV1 {
        version("RH", "0x1a2b5c6d")
    }

    fn ours() -> ClientVersionV1 {
        version("LA", "0x3c4d7e8f")
    }

    fn graffiti(text: &str) -> Bytes32 {
        let mut bytes = [0u8; GRAFFITI_BYTES];
        bytes[..text.len()].copy_from_slice(text.as_bytes());
        H256(bytes)
    }

    fn appended(text: &str, el: Option<&ClientVersionV1>) -> String {
        display(&with_client_versions(graffiti(text), el, &ours()))
    }

    #[test]
    fn empty_graffiti_gets_the_whole_suffix_without_a_space() {
        assert_eq!(appended("", Some(&reth())), "RH1a2bLA3c4d");
    }

    /// Every tier boundary of the table in the module doc, on both sides.
    #[test]
    fn the_suffix_shrinks_to_fit_the_proposers_text() {
        let cases = [
            (19, " RH1a2bLA3c4d"),
            (20, " RH1aLA3c"),
            (23, " RH1aLA3c"),
            (24, " RHLA"),
            (27, " RHLA"),
            (28, " RH"),
            (29, " RH"),
            (30, ""),
            (32, ""),
        ];
        for (len, suffix) in cases {
            let text = "a".repeat(len);
            assert_eq!(
                appended(&text, Some(&reth())),
                format!("{text}{suffix}"),
                "{len} bytes of text"
            );
        }
    }

    #[test]
    fn without_the_execution_clients_version_only_this_clients_half_is_appended() {
        assert_eq!(appended("", None), "LA3c4d");
        let cases = [(25, " LA3c4d"), (26, " LA"), (29, " LA"), (30, "")];
        for (len, suffix) in cases {
            let text = "a".repeat(len);
            assert_eq!(
                appended(&text, None),
                format!("{text}{suffix}"),
                "{len} bytes of text"
            );
        }
    }

    /// Measured in bytes, which is what the field holds: two-byte characters
    /// leave half the room their count suggests.
    #[test]
    fn the_proposers_text_is_measured_in_bytes() {
        let text = "ñ".repeat(10);
        assert_eq!(text.len(), 20);
        assert_eq!(appended(&text, Some(&reth())), format!("{text} RH1aLA3c"));
    }

    #[test]
    fn a_lowercase_code_and_an_uppercase_commit_are_normalized() {
        let el = version("rh", "0X1A2B5C6D");
        assert_eq!(appended("", Some(&el)), "RH1a2bLA3c4d");
    }

    #[test]
    fn a_commit_without_its_prefix_is_accepted() {
        let el = version("RH", "1a2b5c6d");
        assert_eq!(appended("", Some(&el)), "RH1a2bLA3c4d");
    }

    /// A version that does not look like one is left out rather than written
    /// into every block this node produces.
    #[test]
    fn a_malformed_execution_client_version_is_treated_as_absent() {
        for el in [
            version("R", "0x1a2b5c6d"),
            version("R1", "0x1a2b5c6d"),
            version("RHX", "0x1a2b5c6d"),
            version("RH", "0x1a2"),
            version("RH", "0xzzzz5c6d"),
        ] {
            assert_eq!(appended("", Some(&el)), "LA3c4d", "{el:?}");
        }
    }

    #[test]
    fn a_build_without_git_metadata_still_names_this_client() {
        let unversioned = version("LA", "0xVERGEN_I");
        let result = display(&with_client_versions(
            graffiti(""),
            Some(&reth()),
            &unversioned,
        ));
        assert_eq!(result, "RH1a2bLA0000");
    }

    /// Only trailing zeros are padding; one inside the text is part of it.
    #[test]
    fn an_interior_zero_byte_is_kept() {
        let mut bytes = [0u8; GRAFFITI_BYTES];
        bytes[..3].copy_from_slice(b"a\0b");
        let result = with_client_versions(H256(bytes), Some(&reth()), &ours());
        assert_eq!(&result.0[..16], b"a\0b RH1a2bLA3c4d");
        assert!(result.0[16..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn full_graffiti_is_returned_unchanged() {
        let full = H256([b'x'; GRAFFITI_BYTES]);
        assert_eq!(with_client_versions(full, Some(&reth()), &ours()), full);
    }
}
