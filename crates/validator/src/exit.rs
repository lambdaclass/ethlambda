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
//! One of the chain's rules cannot be checked from here: from electra on, a
//! validator with a partial withdrawal still pending is refused
//! (`get_pending_balance_to_withdraw(state, index) == 0`). That refusal comes
//! back as the node's 400, with the node's reason.
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

use ethlambda_types::beacon::constants::FAR_FUTURE_EPOCH;
use ethlambda_types::beacon::containers::shared::{SignedVoluntaryExit, VoluntaryExit};
use ethlambda_types::beacon::preset::SLOTS_PER_EPOCH;
use ethlambda_types::beacon::primitives::{BlsPubkey, Epoch};
use tracing::info;
use zeroize::Zeroizing;

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

/// How many epochs the command waits for the chain to process an exit it
/// published. A node that accepted one has it in a block within a slot or
/// two, so this rides out a run of missed slots and still lets a run end: an
/// exit the chain has not processed by then is not one more slot away.
const WAIT_EPOCHS: u64 = 2;

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
    /// The exit's epoch, before which the chain refuses it. `None` means the
    /// current one. A later epoch needs `presign`: a node refuses an exit
    /// whose epoch has not come, so the command refuses to publish one.
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
    /// then said about the validator, or `None` under `no_wait` and when the
    /// chain had not processed the exit by the end of the wait.
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
    // Scrubbed on drop, like the secret `decrypt` yields from it.
    let password = Zeroizing::new(password);
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
    // The chain refuses an exit before its own epoch, so publishing one is a
    // trip through the prompt to a node's 400. Holding it until then is what
    // `presign` is for.
    if !options.presign && epoch > current_epoch {
        return Err(Error::ExitRefused(format!(
            "the exit's epoch {epoch} has not come (the current epoch is {current_epoch}), so a \
             beacon node would refuse it; pass --presign to sign it now and publish it then"
        )));
    }
    let details = eligible_for_exit(node, &pubkey, epoch, current_epoch, &signing).await?;

    let exit = VoluntaryExit {
        epoch,
        validator_index: details.index,
    };
    let signature = signing.sign_voluntary_exit(store, &pubkey, &exit, current_epoch)?;
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

    let accepted = wait_for_acceptance(node, &pubkey, &clock).await;
    Ok(Outcome::Published { accepted })
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
/// naming `epoch`: active, not already exiting, and past its shard committee
/// period. The same gate `process_voluntary_exit` applies, checked here so
/// the refusal names the reason instead of arriving as a node's 400.
///
/// The chain measures the shard committee period against the epoch it
/// processes the exit in, not the one the exit names, and the earliest that
/// can be is `max(current_epoch, epoch)`: now, for an exit whose epoch has
/// come, and its own epoch for a pre-signed one that has not. So an exit
/// naming an old epoch is as eligible as one naming the current epoch, and a
/// pre-signed one is checked against the epoch it is signed for.
async fn eligible_for_exit<B: BeaconNodeApi + ?Sized>(
    node: &B,
    pubkey: &BlsPubkey,
    epoch: Epoch,
    current_epoch: Epoch,
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
    if current_epoch.max(epoch) < eligible_epoch {
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
/// exit, reporting what it said, for up to [`WAIT_EPOCHS`]. `None` when it had
/// not by then.
///
/// Nothing here fails the run. The exit is already published, so a node that
/// cannot answer one poll is asked again at the next, and a wait that runs out
/// says the exit went out rather than reporting an error for it.
///
/// "Processed" is read off the registry entry, not the status string: the
/// chain gives a validator an exit epoch when it initiates its exit and never
/// takes it back. That ends the wait on every status that follows
/// (`active_exiting`, the `exited_*` and `withdrawal_*` ones a late poll or a
/// short withdrawability delay lands on) and on `active_slashed`, a validator
/// slashed while this waited, which is on its way out too.
async fn wait_for_acceptance<B: BeaconNodeApi + ?Sized>(
    node: &B,
    pubkey: &BlsPubkey,
    clock: &SlotClock,
) -> Option<ValidatorDetails> {
    let slot_duration = clock.slot_duration();
    for _ in 0..WAIT_EPOCHS * SLOTS_PER_EPOCH {
        tokio::time::sleep(slot_duration).await;
        let details = match node.validator(pubkey).await {
            Ok(Some(details)) if details.exit_epoch != FAR_FUTURE_EPOCH => details,
            Ok(_) => {
                eprintln!("Waiting for the chain to accept the voluntary exit...");
                continue;
            }
            Err(err) => {
                eprintln!("Could not read the validator's status, asking again next slot: {err}");
                continue;
            }
        };
        match details.status.as_str() {
            "active_exiting" => {
                // Before genesis there is no exit to wait for, so the clock
                // has an epoch here; zero only keeps this from being a panic.
                let current_epoch = clock.now().map_or(0, |slot| clock.epoch_of(slot));
                let slots_to_go = details
                    .exit_epoch
                    .saturating_sub(current_epoch)
                    .saturating_mul(SLOTS_PER_EPOCH);
                let seconds_to_go = slot_duration
                    .saturating_mul(u32::try_from(slots_to_go).unwrap_or(u32::MAX))
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
            }
            "active_slashed" => eprintln!(
                "The validator was slashed, and leaves the validator set at epoch {}.",
                details.exit_epoch
            ),
            _ => eprintln!("The validator exited at epoch {}.", details.exit_epoch),
        }
        return Some(details);
    }
    eprintln!(
        "The voluntary exit was published, but the chain has not processed it after {WAIT_EPOCHS} \
         epochs. Check the validator's status later; if it is still active_ongoing, run the \
         command again."
    );
    None
}

/// Print a pre-signed exit the way the command does: as pretty JSON on stdout
/// and nothing else there, so it pipes into a file or another tool.
pub fn print_presigned(signed: &SignedVoluntaryExit) -> Result<()> {
    let json = serde_json::to_string_pretty(signed).map_err(|err| Error::Io {
        path: "stdout".to_string(),
        source: err.into(),
    })?;
    println!("{json}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::time::Duration;

    use ethlambda_types::beacon::config::Config;
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

    fn now() -> Epoch {
        let clock = SlotClock::from_config(genesis().genesis_time, &Config::mainnet());
        clock.epoch_of(clock.now().expect("after genesis"))
    }

    /// The chain refuses an exit before `activation_epoch +
    /// SHARD_COMMITTEE_PERIOD`; so does this, naming the epoch it becomes
    /// possible at, which a node's 400 would not.
    #[tokio::test]
    async fn a_validator_inside_its_shard_committee_period_is_refused() {
        let activation = now() - 1;
        let eligible = activation + Config::mainnet().shard_committee_period;
        let node = node_with(active(activation));
        let no_prompt = ExitOptions {
            no_confirmation: true,
            no_wait: true,
            ..ExitOptions::default()
        };
        let err = run(&node, no_prompt, "").await.expect_err("must refuse");
        assert!(
            matches!(&err, Error::ExitRefused(reason) if reason.contains(&format!("before epoch {eligible}"))),
            "got {err:?}"
        );
        assert!(node.submitted_exits().is_empty());

        // A pre-signed exit is checked against the epoch it is signed for:
        // one short of eligibility is refused, the eligible epoch is not.
        for (epoch, signs) in [(eligible - 1, false), (eligible, true)] {
            let presign = ExitOptions {
                epoch: Some(epoch),
                presign: true,
                ..ExitOptions::default()
            };
            let outcome = run(&node, presign, "").await;
            assert_eq!(outcome.is_ok(), signs, "epoch {epoch}: {outcome:?}");
        }
    }

    /// The chain measures the shard committee period against the epoch it
    /// processes the exit in, not the one the exit names, so an exit naming
    /// an epoch from before the validator was eligible, epoch 0 included, is
    /// one it accepts from a validator that is eligible now.
    #[tokio::test]
    async fn an_exit_naming_a_past_epoch_is_published_for_an_eligible_validator() {
        let node = node_with(active(0));
        for epoch in [0, Config::mainnet().shard_committee_period - 1] {
            let options = ExitOptions {
                epoch: Some(epoch),
                no_confirmation: true,
                no_wait: true,
                ..ExitOptions::default()
            };
            run(&node, options, "").await.expect("publishes");
            let published = node.submitted_exits();
            assert_eq!(published.last().expect("one more").message.epoch, epoch);
        }
    }

    /// A node refuses an exit whose epoch has not come, so the command does
    /// not walk the operator through the prompt to that 400.
    #[tokio::test]
    async fn an_exit_for_a_future_epoch_is_not_published_without_presign() {
        let node = node_with(active(0));
        let options = ExitOptions {
            epoch: Some(now() + 1),
            no_confirmation: true,
            no_wait: true,
            ..ExitOptions::default()
        };
        let err = run(&node, options, "").await.expect_err("must refuse");
        assert!(
            matches!(&err, Error::ExitRefused(reason) if reason.contains("--presign")),
            "got {err:?}"
        );
        assert!(node.submitted_exits().is_empty());
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
        let root = signing.voluntary_exit_signing_root(&signed.message, now());
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
        assert_eq!(node.submitted_exits()[0].message.epoch, now());
    }

    fn exiting(status: &str) -> ValidatorDetails {
        ValidatorDetails {
            status: status.to_string(),
            exit_epoch: 1_000_000,
            withdrawable_epoch: 1_000_256,
            ..active(0)
        }
    }

    fn waits() -> ExitOptions {
        ExitOptions {
            no_confirmation: true,
            ..ExitOptions::default()
        }
    }

    /// With `start_paused`, the once-a-slot sleep completes at once, so the
    /// wait loop is exercised without waiting a slot. The exit is checked
    /// against the active entry; the node answers with the other one from the
    /// moment it has the exit, as a chain that processed it would.
    ///
    /// Every status that follows an initiated exit ends the wait, not only
    /// `active_exiting`: a late poll lands on a later one, and a validator
    /// slashed meanwhile is leaving too.
    #[tokio::test(start_paused = true)]
    async fn the_wait_ends_once_the_chain_has_given_the_validator_an_exit_epoch() {
        for status in [
            "active_exiting",
            "active_slashed",
            "exited_unslashed",
            "exited_slashed",
            "withdrawal_possible",
            "withdrawal_done",
        ] {
            let node = node_with(active(0)).with_details_after_exit(exiting(status));
            let outcome = run(&node, waits(), "").await.expect("published");
            assert_eq!(
                outcome,
                Outcome::Published {
                    accepted: Some(exiting(status))
                },
                "{status}"
            );
        }
    }

    /// An exit the chain never processes does not hold the command forever,
    /// and is not an error either: it was published.
    #[tokio::test(start_paused = true)]
    async fn the_wait_gives_up_on_an_exit_the_chain_does_not_process() {
        let node = node_with(active(0));
        let started = tokio::time::Instant::now();
        let outcome = run(&node, waits(), "").await.expect("published");
        assert_eq!(outcome, Outcome::Published { accepted: None });
        assert_eq!(node.submitted_exits().len(), 1);

        let slot = Duration::from_millis(Config::mainnet().slot_duration_ms);
        let waited = slot.saturating_mul((WAIT_EPOCHS * SLOTS_PER_EPOCH) as u32);
        assert_eq!(started.elapsed(), waited);
    }

    /// Once the exit is out, a node that cannot answer is not a failed run:
    /// reporting an error for an exit that was published would say the
    /// opposite of what happened. The node is asked again, and the run ends
    /// with what it says once it answers.
    #[tokio::test(start_paused = true)]
    async fn a_node_that_cannot_answer_after_the_publish_is_asked_again() {
        let node = node_with(active(0)).with_details_after_exit(exiting("active_exiting"));
        let (store, pubkey) = store_with_key();
        let options = waits();
        let mut input = Cursor::new(String::new());
        let slot = Duration::from_millis(Config::mainnet().slot_duration_ms);
        let started = tokio::time::Instant::now();

        let run = run_with(&node, &store, pubkey, &options, &mut input);
        // The registry lookup fails from the moment the exit is in, for three
        // slots. Time is paused, so it only moves once both futures sleep,
        // and the first poll cannot come before the failure is in place.
        let outage = async {
            while node.submitted_exits().is_empty() {
                tokio::task::yield_now().await;
            }
            let failure = "connection refused".to_string();
            node.failures
                .lock()
                .expect("lock")
                .insert("validator", failure);
            tokio::time::sleep(slot * 3).await;
            node.stop_failing("validator");
        };
        let (outcome, ()) = tokio::join!(run, outage);

        assert_eq!(
            outcome.expect("published"),
            Outcome::Published {
                accepted: Some(exiting("active_exiting"))
            }
        );
        assert!(
            started.elapsed() >= slot * 3,
            "the polls during the outage must have failed, not been skipped"
        );
    }
}
