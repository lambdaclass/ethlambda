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
use axum::routing::{get, post};
use axum::{Extension, Router};
use subtle::ConstantTimeEq as _;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::Error;
use crate::beacon_node::BeaconNodeApi;
use crate::proposer_settings::ProposerSettings;
use crate::secure_fs;
use crate::signing::SigningContext;
use crate::slot_clock::SlotClock;

pub mod keystores;
pub mod proposer;
pub mod remotekeys;
pub mod voluntary_exit;

pub use keystores::SharedStore;

/// Everything the keymanager handlers need: the validator store, the
/// per-validator proposal settings, plus the directories an import or delete
/// must write through so the change survives a restart. Held as the axum state
/// rather than separate `Extension`s, since the routes share most of it.
#[derive(Clone)]
pub struct KeymanagerContext {
    pub store: SharedStore,
    /// Each validator's fee recipient, graffiti and gas limit, which the
    /// `proposer` routes override and a keystore delete forgets.
    pub settings: Arc<ProposerSettings>,
    pub validators_dir: PathBuf,
    pub secrets_dir: PathBuf,
    /// Serializes the open-mutate-save cycle over the validator definitions
    /// file across concurrent import, delete and proposer-settings requests.
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
    /// Every keymanager handler that changes the store or the file holds it
    /// until both changes are done, so the two are always judged and changed
    /// together: a handler that released it between writing the file and
    /// inserting into the store would let a concurrent delete land in the
    /// gap and leave memory and disk disagreeing.
    ///
    /// The duty loop never takes it, so holding it across the slow EIP-2335
    /// key derivation an import performs stalls only other keymanager
    /// requests, a `feerecipient`, `graffiti` or `gas_limit` call among
    /// them: one made during a full import waits for the import to finish.
    /// Where a handler needs both, it takes this one first and
    /// `store` second, consistently, so the two never deadlock against each
    /// other, and it holds `store` only for in-memory work, never across file
    /// I/O or the derivation.
    pub definitions_lock: Arc<Mutex<()>>,
    /// `--web3signer-url`: the signer a remote key imported without a `url`
    /// of its own is assigned to. `None` makes such an import an error.
    pub default_remote_signer: Option<String>,
    /// Where the `voluntary_exit` route resolves a key's validator index.
    pub beacon_node: Arc<dyn BeaconNodeApi>,
    /// What the `voluntary_exit` route signs with.
    pub signing: Arc<SigningContext>,
    /// What the `voluntary_exit` route reads the current epoch from when the
    /// caller names none.
    pub clock: SlotClock,
    /// Whether the last save of the definitions file replaced it without
    /// flushing the directory, so its last change may not survive a power
    /// loss. Set and cleared by `keystores::save_definitions`; read where a
    /// retry would otherwise report that change as final.
    pub definitions_unflushed: Arc<std::sync::atomic::AtomicBool>,
    /// The record every key must be registered in before it is loaded, so the
    /// duty path never meets a key it has no record for.
    pub protection: crate::slashing_protection::SharedProtection,
}

/// The file the generated token is written to, inside the validators directory.
/// Neither read nor written when `--keymanager-token-file` names another file.
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

/// The keymanager API's bearer token: read from `token_file` when the operator
/// named one (`--keymanager-token-file`), otherwise from [`API_TOKEN_FILE`] in
/// `validators_dir`, generated there if absent.
pub fn load_token(validators_dir: &Path, token_file: Option<&Path>) -> crate::Result<String> {
    match token_file {
        Some(path) => load_token_file(path),
        None => load_or_create_token(validators_dir),
    }
}

/// Read the API token from a file the operator supplies, with the checks
/// [`load_or_create_token`] applies to its own file.
///
/// Read only: nothing here writes or creates `path`. The file is the
/// operator's, typically one token shared with tooling that calls several
/// clients' keymanager APIs, so a missing or unusable file is an error rather
/// than a cue to generate a token that tooling would not hold.
fn load_token_file(path: &Path) -> crate::Result<String> {
    let contents = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.display().to_string(),
        source,
    })?;
    let remedy =
        format!("write a token of at least {MIN_TOKEN_LEN} visible ASCII characters to it");
    let token = checked_token(path, &contents, &remedy)?;
    info!(path = %path.display(), "Read the keymanager API token");
    Ok(token)
}

/// `contents` trimmed, or an error if that is not a token a request can
/// carry, or is shorter than [`MIN_TOKEN_LEN`]. `remedy` ends the error,
/// telling the operator what to do about it.
fn checked_token(path: &Path, contents: &str, remedy: &str) -> crate::Result<String> {
    let token = contents.trim();
    // A request carries the token in its `Authorization` header, which
    // `require_bearer` reads only as visible ASCII, and a bearer token has no
    // spaces in it (RFC 6750). A token with anything else would start the
    // client with a keymanager API no request can authenticate to. Checked
    // first, so the length below counts characters as well as bytes.
    if let Some(unusable) = token.chars().find(|c| !c.is_ascii_graphic()) {
        return Err(Error::Keystore {
            path: path.display().to_string(),
            reason: format!(
                "the API token file holds {unusable:?}, which a bearer token cannot carry \
                 (only visible ASCII characters, and no spaces inside); {remedy}"
            ),
        });
    }
    if token.len() < MIN_TOKEN_LEN {
        return Err(Error::Keystore {
            path: path.display().to_string(),
            reason: format!(
                "the API token file holds {} characters, which is below the {MIN_TOKEN_LEN} \
                 required; {remedy}",
                token.len()
            ),
        });
    }
    Ok(token.to_string())
}

/// Read the API token from [`API_TOKEN_FILE`] in `validators_dir`, generating
/// one if the file does not exist.
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
        Ok(contents) => checked_token(&path, &contents, "delete it to have a new token generated"),
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
        .route(
            "/eth/v1/remotekeys",
            get(remotekeys::list)
                .post(remotekeys::import)
                .delete(remotekeys::delete),
        )
        .route(
            "/eth/v1/validator/{pubkey}/feerecipient",
            get(proposer::get_fee_recipient)
                .post(proposer::set_fee_recipient)
                .delete(proposer::delete_fee_recipient),
        )
        .route(
            "/eth/v1/validator/{pubkey}/graffiti",
            get(proposer::get_graffiti)
                .post(proposer::set_graffiti)
                .delete(proposer::delete_graffiti),
        )
        .route(
            "/eth/v1/validator/{pubkey}/gas_limit",
            get(proposer::get_gas_limit)
                .post(proposer::set_gas_limit)
                .delete(proposer::delete_gas_limit),
        )
        .route(
            "/eth/v1/validator/{pubkey}/voluntary_exit",
            post(voluntary_exit::create_signed_voluntary_exit),
        )
        .with_state(context)
        .layer(middleware::from_fn(require_bearer))
        .layer(Extension(ApiToken(token)))
        // `POST /eth/v1/keystores` carries a whole EIP-3076 interchange, which
        // in the complete format for a batch of validators runs past axum's
        // 2 MB default. Nimbus allows 16 MiB and Lodestar 20 MB; Lighthouse
        // and Prysm set no limit.
        .layer(axum::extract::DefaultBodyLimit::max(KEYMANAGER_BODY_LIMIT))
}

/// The largest request body the keymanager API reads.
const KEYMANAGER_BODY_LIMIT: usize = 64 * 1024 * 1024;

/// Serve the keymanager API on `listener` until `shutdown` is cancelled, then
/// stop accepting requests and return once the ones in flight have answered.
///
/// Stopping that way matters to an import. It saves its keys before it
/// registers them, and takes them off disk again if the registration fails
/// (see [`keystores::import`]). Dropped in between, as it would be if the
/// runtime went away under it, it leaves keys that are saved and enabled with
/// no slashing-protection record, which the next start refuses, and the start
/// after that.
pub async fn serve(
    listener: tokio::net::TcpListener,
    router: Router,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The three `voluntary_exit` fields for a test that is not about that
    /// route: a mock node resolving no validator, mainnet's schedule and a
    /// clock started at the Unix epoch.
    pub(crate) fn exit_route_context() -> (Arc<dyn BeaconNodeApi>, Arc<SigningContext>, SlotClock) {
        use ethlambda_types::beacon::config::Config;
        use ethlambda_types::beacon::primitives::Root;

        let config = Config::mainnet();
        let clock = SlotClock::from_config(0, &config);
        let signing = Arc::new(SigningContext::new(config, Root::ZERO));
        let node = Arc::new(crate::beacon_node::mock::MockBeaconNode::new());
        (node, signing, clock)
    }
}

#[cfg(all(test, unix))]
mod token_tests {
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

    /// A `--keymanager-token-file`'s contents as an operator might write them,
    /// with whitespace around the token and a trailing newline.
    const SUPPLIED: &str = "  a-token-an-operator-picked\n";

    #[test]
    fn a_supplied_token_file_is_read_trimmed_and_left_as_it_was() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("keymanager.txt");
        std::fs::write(&path, SUPPLIED).expect("writes it");

        let token = load_token_file(&path).expect("accepted");

        assert_eq!(token, "a-token-an-operator-picked");
        let after = std::fs::read_to_string(&path).expect("still there");
        assert_eq!(after, SUPPLIED, "the file is read, never rewritten");
    }

    #[test]
    fn a_short_supplied_token_file_is_refused_without_suggesting_its_deletion() {
        // Deleting a supplied file only turns this error into a missing-file
        // one, so the advice the generated file's error gives would be wrong.
        for contents in ["", "   \n\t  \n", "abc"] {
            let dir = tempfile::tempdir().expect("temp dir");
            let path = dir.path().join("keymanager.txt");
            std::fs::write(&path, contents).expect("writes it");

            let err = load_token_file(&path).expect_err("a short token must be refused");

            let Error::Keystore { reason, .. } = err else {
                panic!("expected the length refusal, got {err}");
            };
            assert!(reason.contains("below the"), "should say why: {reason}");
            assert!(!reason.contains("delete"), "wrong remedy: {reason}");
        }
    }

    #[test]
    fn a_supplied_token_no_request_could_carry_is_refused() {
        // Long enough, but `require_bearer` reads the header only as visible
        // ASCII and a bearer token has no spaces, so each would start a
        // keymanager API no request can authenticate to.
        for contents in [
            "token-for-all-clients-\u{fc}",
            "a-token-an-operator\npicked",
            "a-token-an operator-picked",
        ] {
            let dir = tempfile::tempdir().expect("temp dir");
            let path = dir.path().join("keymanager.txt");
            std::fs::write(&path, contents).expect("writes it");

            let err = load_token_file(&path).expect_err("an unusable token must be refused");

            let Error::Keystore { reason, .. } = err else {
                panic!("expected the character refusal, got {err}");
            };
            assert!(reason.contains("cannot carry"), "should say why: {reason}");
        }
    }

    #[test]
    fn a_missing_supplied_token_file_is_an_error_and_is_not_created() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("keymanager.txt");

        let err = load_token_file(&path).expect_err("a missing file must not be generated");

        assert!(
            matches!(&err, Error::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound),
            "got {err}"
        );
        assert!(!path.exists(), "the supplied path must never be written");
    }

    #[test]
    fn with_a_token_file_the_validators_directory_gets_no_token_of_its_own() {
        let validators_dir = tempfile::tempdir().expect("temp dir");
        let supplied_dir = tempfile::tempdir().expect("temp dir");
        let path = supplied_dir.path().join("keymanager.txt");
        let generated = validators_dir.path().join(API_TOKEN_FILE);

        // Missing: an error, not a fallback to the generated file.
        load_token(validators_dir.path(), Some(&path)).expect_err("a missing file is an error");
        assert!(!generated.exists());
        assert!(!path.exists());

        std::fs::write(&path, SUPPLIED).expect("writes it");
        let token = load_token(validators_dir.path(), Some(&path)).expect("accepted");
        assert_eq!(token, "a-token-an-operator-picked");
        assert!(!generated.exists());
    }

    #[test]
    fn a_supplied_token_file_wins_over_an_existing_generated_one() {
        let validators_dir = tempfile::tempdir().expect("temp dir");
        let generated = load_or_create_token(validators_dir.path()).expect("generates a token");
        let supplied_dir = tempfile::tempdir().expect("temp dir");
        let path = supplied_dir.path().join("keymanager.txt");
        std::fs::write(&path, SUPPLIED).expect("writes it");

        let token = load_token(validators_dir.path(), Some(&path)).expect("accepted");

        assert_eq!(token, "a-token-an-operator-picked");
        assert_ne!(token, generated);
    }

    #[test]
    fn without_a_token_file_the_token_is_generated_as_before() {
        let dir = tempfile::tempdir().expect("temp dir");

        let token = load_token(dir.path(), None).expect("generates a token");

        let written = std::fs::read_to_string(dir.path().join(API_TOKEN_FILE)).expect("written");
        assert_eq!(token, written);
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
