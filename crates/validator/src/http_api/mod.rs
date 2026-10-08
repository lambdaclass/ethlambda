//! The keymanager API.
//!
//! Bearer-token authenticated and bound to localhost by default. The
//! specification requires TLS; a deployment that exposes this beyond the
//! loopback interface must front it with a TLS terminator, which is the same
//! position Lighthouse and Prysm take.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use subtle::ConstantTimeEq as _;
use tokio::sync::Mutex;
use tracing::info;

use crate::Error;
use crate::secure_fs;

pub mod keystores;

pub use keystores::SharedStore;

/// Everything the keymanager handlers need: the validator store, plus the
/// directories an import or delete must write through so the change survives
/// a restart. Held as the axum state rather than three separate `Extension`s,
/// since every route needs all three together.
#[derive(Clone)]
pub struct KeymanagerContext {
    pub store: SharedStore,
    pub validators_dir: PathBuf,
    pub secrets_dir: PathBuf,
    /// Serializes the open-mutate-save cycle over the validator definitions
    /// file across concurrent import/delete requests.
    ///
    /// `store`'s `RwLock` does not close this on its own: an import or delete
    /// takes a fresh [`crate::keys::ValidatorDefinitions`] snapshot from disk
    /// outside of any lock, mutates it, and saves it back, so two requests
    /// each doing that independently can interleave, and one write clobbers
    /// the other. Concretely: a delete removes a key and saves; a concurrent
    /// import that snapshotted the file before that save lands afterwards and
    /// writes the deleted key back as `enabled: true`. This mutex, held by
    /// each handler across its entire read-modify-write cycle (not just
    /// `store`), is what actually orders those cycles.
    ///
    /// Guards the file only, never `store`: holding it across the slow
    /// EIP-2335 key derivation an import performs must not stall the duty
    /// loop, which only ever waits on `store`. Where a handler needs both,
    /// it takes this one first and `store` second, consistently, so the two
    /// never deadlock against each other.
    pub definitions_lock: Arc<Mutex<()>>,
}

/// The file the generated token is written to, inside the validators directory.
pub const API_TOKEN_FILE: &str = "api-token.txt";

/// The shortest token this will accept from an existing file.
///
/// Generated tokens are a 32-character UUID, so this rejects nothing this
/// client writes. It exists for what it refuses: a file that is empty or
/// nearly so, which cannot be a token anyone chose.
///
/// The value matters less than the floor being above zero. See
/// [`load_or_create_token`] for why zero was not safe.
const MIN_TOKEN_LEN: usize = 16;

/// Read the API token, generating one if the file does not exist.
///
/// # An empty file is refused, not accepted
///
/// Returning the trimmed contents of any existing file was an authentication
/// bypass. Two facts combined: this returned `Ok("")` for an empty file, and
/// the comparison in [`require_bearer_token`] uses `subtle`'s `ct_eq`, which
/// returns *true* for two empty slices (its accumulator starts at 1 and the
/// fold body never runs). A request carrying `Authorization: Bearer ` with a
/// trailing space strips to `Some("")`, and empty matched empty.
///
/// It was reachable without anyone doing anything unusual:
/// [`secure_fs::write_private`] opens with `truncate(true)` and then writes,
/// so a first boot that failed between those two steps left a zero-byte file
/// that every later boot accepted.
///
/// Refusing is the right failure here rather than regenerating: a token file
/// that exists but is unusable means something went wrong that an operator
/// should see, and silently minting a new one would change the credential
/// their tooling already holds.
pub fn load_or_create_token(validators_dir: &Path) -> crate::Result<String> {
    let path = validators_dir.join(API_TOKEN_FILE);
    match std::fs::read_to_string(&path) {
        Ok(token) => {
            let token = token.trim().to_string();
            if token.len() < MIN_TOKEN_LEN {
                return Err(Error::Keystore {
                    path: path.display().to_string(),
                    reason: format!(
                        "the API token file holds {} characters, which is below the {MIN_TOKEN_LEN} \
                         required; delete it to have a new token generated",
                        token.len()
                    ),
                });
            }
            Ok(token)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let token = uuid::Uuid::new_v4().simple().to_string();
            secure_fs::write_private(&path, &token).map_err(|source| Error::Io {
                path: path.display().to_string(),
                source,
            })?;
            info!(path = %path.display(), "Generated a keymanager API token");
            Ok(token)
        }
        Err(source) => Err(Error::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

pub fn router(context: KeymanagerContext, token: String) -> Router {
    Router::new()
        .route(
            "/eth/v1/keystores",
            get(keystores::list)
                .post(keystores::import)
                .delete(keystores::delete),
        )
        .with_state(context)
        .layer(middleware::from_fn(require_bearer))
        .layer(Extension(ApiToken(token)))
}

#[derive(Clone)]
struct ApiToken(String);

/// Reject anything without the exact bearer token.
///
/// Deliberately a blanket layer rather than a per-route guard: a route added
/// later is authenticated by default rather than by remembering to add it.
async fn require_bearer(request: Request, next: Next) -> Response {
    let expected = request
        .extensions()
        .get::<ApiToken>()
        .map(|token| token.0.clone());

    let presented = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_string);

    // `==` on `String` short-circuits at the first mismatched byte, which
    // leaks timing information about how much of the token a caller
    // guessed right. This service is localhost-bound by default, but
    // `--http-address` is operator-configurable with nothing enforcing that,
    // so the comparison has to hold even off loopback.
    let matches = match (&expected, &presented) {
        // An empty expected token must never match, independently of
        // `load_or_create_token` refusing to produce one. `ct_eq` returns true
        // for two empty slices, so without this an empty configured token plus
        // a header of `Bearer ` (trailing space) authenticates. `router` takes
        // the token from its caller, so this cannot rely on the loader being
        // the only source. Checking the length first is not a timing leak: the
        // emptiness of the *configured* token is not a secret, and no
        // comparison against the presented value has happened yet.
        (Some(expected), _) if expected.is_empty() => false,
        (Some(expected), Some(presented)) => {
            bool::from(expected.as_bytes().ct_eq(presented.as_bytes()))
        }
        _ => false,
    };

    if matches {
        next.run(request).await
    } else {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(axum::body::Body::empty())
            .expect("static response")
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn the_generated_api_token_file_is_mode_0600() {
        let dir = tempfile::tempdir().expect("temp dir");
        load_or_create_token(dir.path()).expect("generates a token");

        let mode = std::fs::metadata(dir.path().join(API_TOKEN_FILE))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "got {mode:o}");
    }

    #[test]
    fn a_generated_token_is_long_enough_to_be_accepted_on_the_next_boot() {
        // The two halves of `load_or_create_token` must agree: a token it
        // writes must be one it will read back. A `MIN_TOKEN_LEN` raised above
        // the generated length would lock the client out of its own file on
        // restart, and nothing else would catch that.
        let dir = tempfile::tempdir().expect("temp dir");
        let generated = load_or_create_token(dir.path()).expect("generates a token");

        assert!(generated.len() >= MIN_TOKEN_LEN);
        let reloaded = load_or_create_token(dir.path()).expect("reads it back");
        assert_eq!(generated, reloaded);
    }

    /// The authentication bypass this check exists for.
    ///
    /// `secure_fs::write_private` truncates before it writes, so a first boot
    /// that dies between those steps leaves a zero-byte file. Accepting it
    /// produced an empty expected token, and `ct_eq` matches two empty slices,
    /// so `Authorization: Bearer ` with a trailing space authenticated.
    #[test]
    fn an_empty_token_file_is_refused_rather_than_accepted() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join(API_TOKEN_FILE), "").expect("writes an empty file");

        let err = load_or_create_token(dir.path()).expect_err("an empty token must be refused");

        assert!(
            err.to_string().contains("below the"),
            "the error should say why: {err}"
        );
    }

    #[test]
    fn a_whitespace_only_token_file_is_refused() {
        // Trimming turns this into the empty case, so it must fail the same
        // way rather than slipping past on its untrimmed length.
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join(API_TOKEN_FILE), "   \n\t  \n").expect("writes whitespace");

        assert!(load_or_create_token(dir.path()).is_err());
    }

    #[test]
    fn a_short_token_file_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join(API_TOKEN_FILE), "abc").expect("writes a short token");

        assert!(load_or_create_token(dir.path()).is_err());
    }

    #[test]
    fn a_plausible_operator_supplied_token_is_accepted() {
        // The check must not reject a token an operator chose themselves,
        // which is a supported way to run this: only implausibly short ones.
        let dir = tempfile::tempdir().expect("temp dir");
        let chosen = "a-token-an-operator-picked";
        std::fs::write(dir.path().join(API_TOKEN_FILE), chosen).expect("writes it");

        assert_eq!(load_or_create_token(dir.path()).expect("accepted"), chosen);
    }

    /// `ct_eq`'s behaviour on empty slices, pinned here because the
    /// authentication check's correctness depends on it and it is surprising.
    #[test]
    fn subtle_reports_two_empty_slices_as_equal() {
        assert!(
            bool::from(b"".ct_eq(b"")),
            "if this ever becomes false, the empty-token guard is still correct \
             but its stated reason is not"
        );
    }
}
