//! `ethlambda validator exit`: sign a voluntary exit for one keystore and hand
//! it to a beacon node.
//!
//! A voluntary exit is the one thing a validator signs that cannot be taken
//! back: once the chain processes it the validator is queued to leave, stops
//! earning once it has, and the key can never be re-activated. So the command
//! is deliberately slow to pull the trigger. It refuses a node that is still
//! syncing, refuses a validator the chain would refuse (not active, or not yet
//! past `SHARD_COMMITTEE_PERIOD` since activation), signs, and then, unless
//! told not to, asks for a confirmation phrase before publishing anything.
//!
//! `--presign` stops after signing and prints the `SignedVoluntaryExit` as JSON
//! instead, for an operator who wants to hold a signed exit for later. EIP-7044
//! made that useful: from deneb on, exits sign under a fixed fork version, so
//! one signed today still verifies after every fork to come.
//!
//! The command talks to one beacon node. It is not a long-running client, so
//! failover buys it nothing: an operator whose node is down picks another.

use std::io::BufRead;
use std::path::{Path, PathBuf};

use ethlambda_types::beacon::containers::shared::{SignedVoluntaryExit, VoluntaryExit};
use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch};
use tracing::info;

use crate::beacon_node::dto::encode_hex;
use crate::beacon_node::http::HttpBeaconNode;
use crate::beacon_node::{BeaconNodeApi, ValidatorDetails};
use crate::error::{Error, Result};
use crate::keys::ValidatorStore;
use crate::keys::keystore::Keystore;
use crate::signing::SigningContext;
use crate::slot_clock::SlotClock;

/// What the operator must type to publish. The same phrase Lighthouse asks
/// for, so an operator moving between the two has one thing to remember.
pub const CONFIRMATION_PHRASE: &str = "Exit my validator";

/// Everything the command is configured with.
#[derive(Debug, Clone)]
pub struct ExitConfig {
    /// The EIP-2335 voting keystore of the validator to exit.
    pub keystore: PathBuf,
    /// The file holding that keystore's password.
    pub password_file: PathBuf,
    /// Base URL of the beacon node's HTTP API.
    pub beacon_node: String,
    pub options: ExitOptions,
}

/// The flags that shape the run, apart from where the key and the node are.
#[derive(Debug, Clone, Default)]
pub struct ExitOptions {
    /// The exit's epoch. `None` means the current one. A later epoch only makes
    /// sense with `presign`: a node refuses an exit whose epoch has not come.
    pub epoch: Option<Epoch>,
    /// Sign and print the exit as JSON without publishing it.
    pub presign: bool,
    /// Publish without asking for [`CONFIRMATION_PHRASE`].
    pub no_confirmation: bool,
    /// Return as soon as the node has accepted the exit, without waiting for
    /// the chain to process it.
    pub no_wait: bool,
}

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// `presign`: the signed exit, which nobody has published.
    Presigned(SignedVoluntaryExit),
    /// The operator did not type the phrase, so nothing was published.
    NotConfirmed,
    /// The node accepted the exit for gossip. `accepted` is what the chain
    /// then said about the validator, or `None` under `no_wait`.
    Published { accepted: Option<ValidatorDetails> },
}

/// Decrypt the keystore and run the exit against the configured node. Input
/// for the confirmation phrase is the process's stdin.
pub async fn run(config: ExitConfig) -> Result<Outcome> {
    let (store, pubkey) = load_keystore(&config.keystore, &config.password_file)?;
    let node = HttpBeaconNode::new(&config.beacon_node)?;
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    run_with(&node, &store, pubkey, &config.options, &mut input).await
}

/// Decrypt one keystore into a store holding only its key.
///
/// The password file is read the way `ValidatorStore::load` reads one: whole,
/// with a trailing newline trimmed, since an editor leaves one and a password
/// ending in a newline is not something anyone chose.
pub fn load_keystore(
    keystore_path: &Path,
    password_path: &Path,
) -> Result<(ValidatorStore, BlsPubkey)> {
    let json = std::fs::read_to_string(keystore_path).map_err(|source| Error::Io {
        path: keystore_path.display().to_string(),
        source,
    })?;
    let keystore = Keystore::from_json(&json).map_err(|err| Error::Keystore {
        path: keystore_path.display().to_string(),
        reason: err.to_string(),
    })?;
    let password = std::fs::read_to_string(password_path).map_err(|source| Error::Io {
        path: password_path.display().to_string(),
        source,
    })?;
    let secret = keystore
        .decrypt(password.trim_end_matches(['\n', '\r']))
        .map_err(|err| Error::Keystore {
            path: keystore_path.display().to_string(),
            reason: err.to_string(),
        })?;
    let mut store = ValidatorStore::new();
    let pubkey = store.insert_secret(&keystore_path.display().to_string(), &secret)?;
    Ok((store, pubkey))
}

/// The run itself, against any node and any source of the confirmation
/// phrase, which is what the tests drive.
pub async fn run_with<B: BeaconNodeApi + ?Sized>(
    node: &B,
    store: &ValidatorStore,
    pubkey: BlsPubkey,
    options: &ExitOptions,
    input: &mut dyn BufRead,
) -> Result<Outcome> {
    let genesis = node.genesis().await?;
    let spec = node.spec().await?;
    let clock = SlotClock::from_config(genesis.genesis_time, &spec);
    let signing = SigningContext {
        config: spec,
        genesis_validators_root: genesis.genesis_validators_root,
    };

    // A syncing node's registry is behind the chain's, so its answer about
    // the validator's status and index is not one to sign over.
    if node.is_optimistic_or_syncing().await? {
        return Err(Error::BeaconNodeSyncing);
    }

    let current_epoch = current_epoch(&clock)?;
    let epoch = options.epoch.unwrap_or(current_epoch);
    let details = eligible_for_exit(node, &pubkey, epoch, &signing).await?;

    let exit = VoluntaryExit {
        epoch,
        validator_index: details.index,
    };
    let signature = signing.sign_voluntary_exit(store, &pubkey, &exit)?;
    let signed = SignedVoluntaryExit {
        message: exit,
        signature,
    };

    if options.presign {
        info!(
            pubkey = %encode_hex(&pubkey.0),
            validator_index = exit.validator_index,
            epoch,
            "Pre-signed a voluntary exit; nothing was published"
        );
        return Ok(Outcome::Presigned(signed));
    }

    if !options.no_confirmation {
        eprintln!();
        eprintln!(
            "Publishing a voluntary exit for validator {} (index {}) at epoch {epoch}.",
            encode_hex(&pubkey.0),
            exit.validator_index
        );
        eprintln!();
        eprintln!("WARNING: THIS IS AN IRREVERSIBLE OPERATION.");
        eprintln!(
            "Once the chain processes it the validator is queued to exit, stops earning after \
             its exit epoch, and this key can never validate again."
        );
        eprintln!();
        eprintln!(
            "Type the phrase \"{CONFIRMATION_PHRASE}\" to confirm, or anything else to abort:"
        );
        let mut line = String::new();
        input.read_line(&mut line).map_err(|source| Error::Io {
            path: "stdin".to_string(),
            source,
        })?;
        if line.trim() != CONFIRMATION_PHRASE {
            eprintln!(
                "Did not publish the voluntary exit for validator {}: the phrase did not match.",
                encode_hex(&pubkey.0)
            );
            return Ok(Outcome::NotConfirmed);
        }
    }

    node.submit_voluntary_exit(&signed).await?;
    eprintln!(
        "The beacon node accepted the voluntary exit for validator {} and is gossiping it.",
        encode_hex(&pubkey.0)
    );

    if options.no_wait {
        return Ok(Outcome::Published { accepted: None });
    }

    let accepted = wait_for_acceptance(node, &pubkey, &clock).await?;
    Ok(Outcome::Published {
        accepted: Some(accepted),
    })
}

fn current_epoch(clock: &SlotClock) -> Result<Epoch> {
    let slot = clock.now().ok_or_else(|| {
        Error::InconsistentResponse(
            "the beacon node reports a genesis in the future; check the system clock".to_string(),
        )
    })?;
    Ok(clock.epoch_of(slot))
}

/// The validator's registry entry, if the chain would accept an exit for it
/// at `epoch`: active, not already exiting, and past its shard committee
/// period. The same gate `process_voluntary_exit` applies, checked here so
/// the refusal names the reason instead of arriving as a node's 400.
async fn eligible_for_exit<B: BeaconNodeApi + ?Sized>(
    node: &B,
    pubkey: &BlsPubkey,
    epoch: Epoch,
    signing: &SigningContext,
) -> Result<ValidatorDetails> {
    let Some(details) = node.validator(pubkey).await? else {
        return Err(Error::ExitRefused(format!(
            "validator {} is not in the beacon state; check that the node is synced and the \
             validator's deposit has been processed",
            encode_hex(&pubkey.0)
        )));
    };
    if details.status != "active_ongoing" {
        return Err(Error::ExitRefused(format!(
            "validator {} is not eligible for a voluntary exit: its status is {}",
            encode_hex(&pubkey.0),
            details.status
        )));
    }
    let eligible_epoch = details
        .activation_epoch
        .checked_add(signing.config.shard_committee_period)
        .ok_or_else(|| {
            Error::InconsistentResponse(format!(
                "validator {} has an activation epoch too high to add SHARD_COMMITTEE_PERIOD to",
                encode_hex(&pubkey.0)
            ))
        })?;
    if epoch < eligible_epoch {
        return Err(Error::ExitRefused(format!(
            "validator {} is not eligible for a voluntary exit before epoch {eligible_epoch} \
             (activated at epoch {}, and SHARD_COMMITTEE_PERIOD is {} epochs)",
            encode_hex(&pubkey.0),
            details.activation_epoch,
            signing.config.shard_committee_period
        )));
    }
    Ok(details)
}

/// Poll the validator's status once a slot until the chain has processed the
/// exit, reporting what it said.
async fn wait_for_acceptance<B: BeaconNodeApi + ?Sized>(
    node: &B,
    pubkey: &BlsPubkey,
    clock: &SlotClock,
) -> Result<ValidatorDetails> {
    let slot_duration = clock.slot_duration();
    loop {
        tokio::time::sleep(slot_duration).await;
        let Some(details) = node.validator(pubkey).await? else {
            return Err(Error::InconsistentResponse(format!(
                "validator {} vanished from the beacon state while waiting for its exit",
                encode_hex(&pubkey.0)
            )));
        };
        match details.status.as_str() {
            "active_exiting" => {
                let current_epoch = current_epoch(clock)?;
                let epochs_to_go = details.exit_epoch.saturating_sub(current_epoch);
                let seconds_to_go = slot_duration
                    .saturating_mul(epochs_to_go.saturating_mul(SLOTS_PER_EPOCH) as u32)
                    .as_secs();
                eprintln!(
                    "The chain has accepted the voluntary exit, but it is not finalized yet. \
                     Finalization may take several minutes or longer, and before it there is a \
                     small chance the exit is reverted."
                );
                eprintln!(
                    "Current epoch: {current_epoch}, exit epoch: {}, withdrawable epoch: {}",
                    details.exit_epoch, details.withdrawable_epoch
                );
                eprintln!(
                    "Keep the validator running until its exit epoch, in roughly {seconds_to_go} \
                     seconds."
                );
                return Ok(details);
            }
            "exited_unslashed" | "exited_slashed" => {
                eprintln!("The validator exited at epoch {}.", details.exit_epoch);
                return Ok(details);
            }
            _ => {
                eprintln!("Waiting for the chain to accept the voluntary exit...");
            }
        }
    }
}

/// Print a pre-signed exit the way the command does: as pretty JSON on stdout
/// and nothing else there, so it pipes into a file or another tool.
pub fn print_presigned(signed: &SignedVoluntaryExit) -> Result<()> {
    let json = serde_json::to_string_pretty(signed)
        .map_err(|err| Error::Decode(format!("could not encode the signed exit: {err}")))?;
    println!("{json}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::constants::FAR_FUTURE_EPOCH;
    use ethlambda_types::beacon::primitives::Root;

    use super::*;
    use crate::beacon_node::Genesis;
    use crate::beacon_node::mock::MockBeaconNode;

    const INDEX: u64 = 77;

    fn secret() -> [u8; 32] {
        hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("valid hex")
            .try_into()
            .expect("32 bytes")
    }

    fn store_with_key() -> (ValidatorStore, BlsPubkey) {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        (store, pubkey)
    }

    /// Genesis far enough back that the current epoch clears mainnet's
    /// `SHARD_COMMITTEE_PERIOD` for a validator activated at epoch 0.
    fn genesis() -> Genesis {
        let config = Config::mainnet();
        let epochs_back = config.shard_committee_period + 10;
        let seconds_back = epochs_back * SLOTS_PER_EPOCH * config.slot_duration_ms / 1000;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs();
        Genesis {
            genesis_time: now - seconds_back,
            genesis_validators_root: Root::repeat_byte(5),
        }
    }

    fn active(activation_epoch: Epoch) -> ValidatorDetails {
        ValidatorDetails {
            index: INDEX,
            status: "active_ongoing".to_string(),
            activation_epoch,
            exit_epoch: FAR_FUTURE_EPOCH,
            withdrawable_epoch: FAR_FUTURE_EPOCH,
        }
    }

    fn node_with(details: ValidatorDetails) -> MockBeaconNode {
        MockBeaconNode {
            genesis: Some(genesis()),
            ..MockBeaconNode::new()
        }
        .with_validator_details(details)
    }

    fn phrase() -> Cursor<String> {
        Cursor::new(format!("{CONFIRMATION_PHRASE}\n"))
    }

    async fn run(node: &MockBeaconNode, options: ExitOptions, input: &str) -> Result<Outcome> {
        let (store, pubkey) = store_with_key();
        let mut input = Cursor::new(input.to_string());
        run_with(node, &store, pubkey, &options, &mut input).await
    }

    #[tokio::test]
    async fn a_syncing_node_is_refused_before_anything_is_signed() {
        let node = MockBeaconNode {
            syncing: true,
            ..node_with(active(0))
        };
        let err = run(&node, ExitOptions::default(), "")
            .await
            .expect_err("must refuse");
        assert!(matches!(err, Error::BeaconNodeSyncing), "got {err:?}");
        assert!(node.submitted_exits().is_empty());
    }

    #[tokio::test]
    async fn a_validator_the_chain_does_not_know_is_refused() {
        let node = MockBeaconNode {
            genesis: Some(genesis()),
            ..MockBeaconNode::new()
        };
        let err = run(&node, ExitOptions::default(), "")
            .await
            .expect_err("must refuse");
        assert!(
            matches!(&err, Error::ExitRefused(reason) if reason.contains("not in the beacon state")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn a_validator_that_is_not_active_is_refused() {
        let node = node_with(ValidatorDetails {
            status: "pending_queued".to_string(),
            ..active(0)
        });
        let err = run(&node, ExitOptions::default(), "")
            .await
            .expect_err("must refuse");
        assert!(
            matches!(&err, Error::ExitRefused(reason) if reason.contains("pending_queued")),
            "got {err:?}"
        );
        assert!(node.submitted_exits().is_empty());
    }

    /// The chain refuses an exit before `activation_epoch +
    /// SHARD_COMMITTEE_PERIOD`; so does this, naming the epoch it becomes
    /// possible at, which a node's 400 would not.
    #[tokio::test]
    async fn a_validator_inside_its_shard_committee_period_is_refused() {
        let activation = 5;
        let node = node_with(active(activation));
        let far_future = ExitOptions {
            epoch: Some(activation + 1),
            presign: true,
            ..ExitOptions::default()
        };
        let err = run(&node, far_future, "").await.expect_err("must refuse");
        let eligible = activation + Config::mainnet().shard_committee_period;
        assert!(
            matches!(&err, Error::ExitRefused(reason) if reason.contains(&format!("before epoch {eligible}"))),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn presign_returns_a_verifying_exit_and_publishes_nothing() {
        use blst::min_pk::{PublicKey, Signature};

        let node = node_with(active(0));
        let (store, pubkey) = store_with_key();
        let options = ExitOptions {
            presign: true,
            epoch: Some(1_000_000),
            ..ExitOptions::default()
        };
        let outcome = run_with(&node, &store, pubkey, &options, &mut phrase())
            .await
            .expect("signs");
        let Outcome::Presigned(signed) = outcome else {
            panic!("expected a presigned exit, got {outcome:?}");
        };
        assert_eq!(signed.message.epoch, 1_000_000);
        assert_eq!(signed.message.validator_index, INDEX);
        assert!(
            node.submitted_exits().is_empty(),
            "presign must not publish"
        );

        let signing = SigningContext {
            config: Config::mainnet(),
            genesis_validators_root: genesis().genesis_validators_root,
        };
        let root = signing.voluntary_exit_signing_root(&signed.message);
        let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
        let sig = Signature::from_bytes(&signed.signature.0).expect("valid signature");
        assert_eq!(
            sig.verify(
                true,
                root.as_slice(),
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
                &[],
                &pk,
                true
            ),
            blst::BLST_ERROR::BLST_SUCCESS
        );
    }

    #[tokio::test]
    async fn a_wrong_phrase_publishes_nothing() {
        let node = node_with(active(0));
        let outcome = run(&node, ExitOptions::default(), "exit my validator\n")
            .await
            .expect("an aborted run is not an error");
        assert_eq!(outcome, Outcome::NotConfirmed);
        assert!(node.submitted_exits().is_empty());
    }

    #[tokio::test]
    async fn the_phrase_publishes_and_no_wait_returns_at_once() {
        let node = node_with(active(0));
        let options = ExitOptions {
            no_wait: true,
            ..ExitOptions::default()
        };
        let outcome = run(&node, options, &format!("{CONFIRMATION_PHRASE}\n"))
            .await
            .expect("publishes");
        assert_eq!(outcome, Outcome::Published { accepted: None });
        let submitted = node.submitted_exits();
        assert_eq!(submitted.len(), 1);
        assert_eq!(submitted[0].message.validator_index, INDEX);
    }

    #[tokio::test]
    async fn no_confirmation_skips_the_prompt() {
        let node = node_with(active(0));
        let options = ExitOptions {
            no_confirmation: true,
            no_wait: true,
            ..ExitOptions::default()
        };
        let outcome = run(&node, options, "").await.expect("publishes");
        assert_eq!(outcome, Outcome::Published { accepted: None });
        assert_eq!(node.submitted_exits().len(), 1);
    }

    /// The exit epoch defaults to the current one, by the client's clock.
    #[tokio::test]
    async fn the_exit_epoch_defaults_to_the_current_epoch() {
        let node = node_with(active(0));
        let options = ExitOptions {
            no_confirmation: true,
            no_wait: true,
            ..ExitOptions::default()
        };
        run(&node, options, "").await.expect("publishes");
        let clock = SlotClock::from_config(genesis().genesis_time, &Config::mainnet());
        let now = clock.epoch_of(clock.now().expect("after genesis"));
        assert_eq!(node.submitted_exits()[0].message.epoch, now);
    }

    /// With `start_paused`, the once-a-slot sleep completes at once, so the
    /// wait loop is exercised without waiting a slot.
    #[tokio::test(start_paused = true)]
    async fn the_wait_ends_once_the_chain_reports_the_validator_exiting() {
        let node = node_with(active(0));
        let (store, pubkey) = store_with_key();
        let exiting = ValidatorDetails {
            status: "active_exiting".to_string(),
            exit_epoch: 1_000_000,
            withdrawable_epoch: 1_000_256,
            ..active(0)
        };
        let options = ExitOptions {
            no_confirmation: true,
            ..ExitOptions::default()
        };
        // The exit is checked against the active entry; the poll then sees
        // the exiting one.
        let mut input = phrase();
        let run = run_with(&node, &store, pubkey, &options, &mut input);
        tokio::pin!(run);
        let flip = async {
            tokio::task::yield_now().await;
            node.set_validator_details(Some(exiting.clone()));
        };
        let (outcome, ()) = tokio::join!(run, flip);
        assert_eq!(
            outcome.expect("published and accepted"),
            Outcome::Published {
                accepted: Some(exiting)
            }
        );
    }
}
