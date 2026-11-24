//! Slashed validators: a loaded key the chain reports slashed is reported,
//! counted and given no more proposer, attester or aggregation duties, and
//! with `--shut-down-when-slashed` the client stops.
//!
//! # Why the other keys are the ones at risk
//!
//! The slashed key itself has little left to lose. It cannot be slashed a
//! second time, a block from it is invalid (`process_block_header` refuses a
//! slashed proposer), and its attestations earn nothing (attestation rewards
//! count only unslashed participants). A slashing means the setup is broken,
//! though: the key runs in a second place, slashing protection was bypassed
//! (a key started with `--init-slashing-protection` that had a history
//! elsewhere, or a record restored from an old backup), or the key leaked.
//! Whatever caused it usually applies to every key that shares the validators
//! directory or the copied setup, and each further key slashed in the same
//! window raises every slashed key's penalty (`process_slashings`).
//!
//! # How a slashing is seen
//!
//! The epoch refresh already resolves every loaded key through
//! `POST /eth/v1/beacon/states/head/validators`, and the answer carries each
//! validator's `slashed` flag. The flag is what is read, not `status`: a
//! status says `active_slashed` or `exited_slashed`, but nothing about a
//! slashing once the validator reaches `withdrawal_possible`. A slashing is in
//! the head state as soon as a block includes it, so it is seen within an
//! epoch of that block. The beacon node's `proposer_slashing` and
//! `attester_slashing` events would cut that to seconds, against a node that
//! emits them; this client does not subscribe to them yet.
//!
//! Each refresh's answer replaces the last one. A slashing cannot be undone,
//! so a key leaves the set only when it is no longer loaded, or when a node's
//! earlier answer was wrong, which then cost the key at most an epoch of
//! duties.
//!
//! # What changes for a slashed key
//!
//! - The first refresh that finds it logs it at error, with its index, pubkey
//!   and status, and `ethlambda_validator_validators_slashed` counts it for as
//!   long as it is loaded.
//! - It gets no more proposals, attestations or aggregations, the ones the
//!   chain refuses or does not reward. [`crate::duties::DutiesService`] still
//!   fetches those duties, and hands none out (see
//!   [`crate::duties::DutiesService::set_slashed`]).
//! - It keeps its sync committee and payload timeliness committee duties,
//!   since the chain still counts both. `process_sync_aggregate` rewards every
//!   participating member with no slashed check and penalises one that
//!   misses, so dropping the duty would only cost the validator. Nothing in
//!   gloas refuses or ignores a slashed member's payload attestation either:
//!   the committee is drawn from the slot's beacon committees, slashed members
//!   included (`compute_ptc`), and neither `process_payload_attestation` nor
//!   the fork choice's `on_payload_attestation_message` reads the flag, so the
//!   vote still counts towards the payload's timeliness.
//! - It is left out of builder registrations, fee recipient preparations and
//!   proposer preferences. It can still hold a proposal slot (before gloas
//!   any slot it is drawn for until it exits; from gloas, where each new draw
//!   leaves slashed validators out, one drawn before the slashing), but its
//!   block would be refused, so there is no proposal for any of them to
//!   describe.
//!
//! # Stopping
//!
//! With `--shut-down-when-slashed`, the first refresh that finds a slashed key
//! stops the client before it sends or fetches anything else for the epoch,
//! and `ethlambda validator` exits with [`EXIT_CODE`]. It is off by default,
//! as Teku's `--shut-down-when-validator-slashed-enabled` is: without it the
//! other keys go on, and the error line and the gauge are what tell the
//! operator.
//!
//! Every start finds the same key again, so a supervisor that restarts the
//! client on failure would restart it into the same stop for as long as the
//! key stays loaded. [`EXIT_CODE`] is its own so the supervisor can be told not
//! to (systemd's `RestartPreventExitStatus=`).
//!
//! The answer is one beacon node's: with several `--beacon-nodes`, the lookup
//! takes the first one that answers, and nothing confirms it against another.
//! A node that wrongly reports a key slashed stops the client with the flag
//! on, and costs that key an epoch of duties without it.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard, PoisonError};

use ethlambda_types::beacon::primitives::{BlsPubkey, ValidatorIndex};
use tracing::error;

use crate::beacon_node::ValidatorEntry;
use crate::beacon_node::dto::encode_hex;
use crate::error::{Error, Result};

/// What `ethlambda validator` exits with when `--shut-down-when-slashed` stops
/// it. Its own, so a supervisor can be told not to restart on it: not the 1
/// any other failure exits with, clap's 2 for a command line it refuses, or
/// the 101 of a panic.
pub const EXIT_CODE: i32 = 3;

/// The loaded keys the chain reports slashed, as of the last epoch refresh,
/// and whether finding one stops the client. Held by
/// [`crate::signing::SigningContext`], so every service that sends something
/// for a key can ask.
#[derive(Debug, Default)]
pub struct SlashedValidators {
    /// `--shut-down-when-slashed`.
    shut_down: bool,
    /// Each slashed key's validator index.
    slashed: Mutex<HashMap<BlsPubkey, ValidatorIndex>>,
}

impl SlashedValidators {
    /// No key slashed yet. With `shut_down`, a refresh that finds one stops the
    /// client.
    pub fn new(shut_down: bool) -> Self {
        Self {
            shut_down,
            ..Self::default()
        }
    }

    /// Take one refresh's answer for the loaded keys: log each key it is the
    /// first to report slashed, set `ethlambda_validator_validators_slashed`,
    /// and refuse to go on when the client is to stop.
    ///
    /// # Errors
    ///
    /// [`Error::ValidatorSlashed`], naming every slashed key's index, when
    /// `--shut-down-when-slashed` is on and any key is slashed.
    pub fn observe(&self, entries: &[ValidatorEntry]) -> Result<()> {
        for entry in self.update(entries) {
            error!(
                validator = entry.index,
                pubkey = %encode_hex(&entry.pubkey.0),
                status = %entry.status,
                "Validator slashed: it gets no more proposer, attester or aggregation duties, \
                 builder registrations, fee recipient preparations or proposer preferences. A \
                 slashing means the setup is broken (the key running in a second place, slashing \
                 protection bypassed, a leaked key), and every key that shares it is at risk: \
                 find the cause"
            );
        }
        let count = self.count();
        crate::metrics::set_validators_slashed(count as u64);
        if !self.shut_down || count == 0 {
            return Ok(());
        }
        let mut validators: Vec<ValidatorIndex> = self.indices().into_iter().collect();
        validators.sort_unstable();
        error!(
            ?validators,
            exit_code = EXIT_CODE,
            "Stopping, as --shut-down-when-slashed asks. Do not restart until the cause is found: \
             whatever got these validators slashed is likely to get the other keys slashed too"
        );
        Err(Error::ValidatorSlashed { validators })
    }

    /// Replace the slashed keys with those `entries` reports, and return the
    /// entries of the ones the last answer did not report.
    fn update<'a>(&self, entries: &'a [ValidatorEntry]) -> Vec<&'a ValidatorEntry> {
        let mut slashed = self.slashed();
        let previous = std::mem::take(&mut *slashed);
        let mut first_seen = Vec::new();
        for entry in entries.iter().filter(|entry| entry.slashed) {
            let repeated = slashed.insert(entry.pubkey, entry.index).is_some();
            if !repeated && !previous.contains_key(&entry.pubkey) {
                first_seen.push(entry);
            }
        }
        first_seen
    }

    /// Whether the last refresh reported `pubkey`'s validator slashed.
    pub fn contains(&self, pubkey: &BlsPubkey) -> bool {
        self.slashed().contains_key(pubkey)
    }

    /// The validator indices of the slashed keys.
    pub fn indices(&self) -> HashSet<ValidatorIndex> {
        self.slashed().values().copied().collect()
    }

    /// How many loaded keys the last refresh reported slashed: what
    /// `ethlambda_validator_validators_slashed` is set to.
    pub fn count(&self) -> usize {
        self.slashed().len()
    }

    /// The map, whatever a panicking holder left it as: every key in it was
    /// reported slashed, and the next refresh replaces it whole.
    fn slashed(&self) -> MutexGuard<'_, HashMap<BlsPubkey, ValidatorIndex>> {
        self.slashed.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::fork::ForkName;
    use ethlambda_types::beacon::primitives::{Bytes32, H160, Root};
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::beacon_node::dto::{AttesterDutyDto, ProposerDutyDto, PtcDutyDto, SyncDutyDto};
    use crate::beacon_node::mock::MockBeaconNode;
    use crate::duties::DutiesService;
    use crate::proposer_settings::ProposerSettings;
    use crate::signing::SigningContext;
    use crate::{Refreshed, preparations, refresh_epoch, run_until_stopped, slashing_protection};

    fn pubkey(byte: u8) -> BlsPubkey {
        BlsPubkey([byte; 48])
    }

    fn entry(index: ValidatorIndex, byte: u8, slashed: bool) -> ValidatorEntry {
        let status = if slashed {
            "active_slashed"
        } else {
            "active_ongoing"
        };
        ValidatorEntry {
            index,
            pubkey: pubkey(byte),
            status: status.to_string(),
            slashed,
        }
    }

    fn first_seen(slashed: &SlashedValidators, entries: &[ValidatorEntry]) -> Vec<ValidatorIndex> {
        slashed
            .update(entries)
            .iter()
            .map(|entry| entry.index)
            .collect()
    }

    /// A key is reported the first time an answer has it slashed, not at every
    /// refresh after. One the next answer leaves out (deleted through the
    /// keymanager API, say) is forgotten, and reported again if it comes back
    /// slashed.
    #[test]
    fn a_key_is_reported_once_and_forgotten_when_no_answer_names_it() {
        let slashed = SlashedValidators::default();
        let entries = [entry(11, 1, false), entry(22, 2, true)];

        assert_eq!(first_seen(&slashed, &entries), [22]);
        assert_eq!(first_seen(&slashed, &entries), Vec::<ValidatorIndex>::new());
        assert!(slashed.contains(&pubkey(2)));
        assert!(!slashed.contains(&pubkey(1)));
        assert_eq!(slashed.indices(), HashSet::from([22]));
        assert_eq!(slashed.count(), 1);

        assert_eq!(
            first_seen(&slashed, &entries[..1]),
            Vec::<ValidatorIndex>::new()
        );
        assert_eq!(slashed.count(), 0);
        assert_eq!(first_seen(&slashed, &entries), [22]);
    }

    fn attester(validator_index: ValidatorIndex, slot: u64) -> AttesterDutyDto {
        AttesterDutyDto {
            pubkey: encode_hex(&[0; 48]),
            validator_index,
            committee_index: 0,
            committee_length: 128,
            committees_at_slot: 64,
            validator_committee_index: 0,
            slot,
        }
    }

    fn proposer(validator_index: ValidatorIndex, slot: u64) -> ProposerDutyDto {
        ProposerDutyDto {
            pubkey: encode_hex(&[0; 48]),
            validator_index,
            slot,
        }
    }

    fn ptc(validator_index: ValidatorIndex, slot: u64) -> PtcDutyDto {
        PtcDutyDto {
            pubkey: encode_hex(&[0; 48]),
            validator_index,
            slot,
        }
    }

    fn sync(validator_index: ValidatorIndex, seat: u64) -> SyncDutyDto {
        SyncDutyDto {
            pubkey: encode_hex(&[0; 48]),
            validator_index,
            validator_sync_committee_indices: vec![seat],
        }
    }

    /// A node that resolves validator 11 (`pubkey(1)`) and validator 22
    /// (`pubkey(2)`), the second slashed, with every kind of duty in epoch 3
    /// for both.
    fn node() -> MockBeaconNode {
        let mut node = MockBeaconNode::new()
            .with_duties(
                3,
                Root::repeat_byte(1),
                vec![attester(11, 100), attester(22, 100)],
            )
            .with_duties(
                4,
                Root::repeat_byte(2),
                vec![attester(11, 130), attester(22, 131)],
            )
            .with_proposers(
                3,
                Root::repeat_byte(1),
                vec![proposer(11, 97), proposer(22, 98)],
            )
            .with_ptc_duties(3, Root::repeat_byte(1), vec![ptc(11, 99), ptc(22, 99)])
            .with_ptc_duties(4, Root::repeat_byte(2), Vec::new())
            .with_sync_duties(0, vec![sync(11, 1), sync(22, 2)]);
        node.validators = vec![entry(11, 1, false), entry(22, 2, true)];
        node
    }

    /// From gloas at genesis, so the refresh fetches every kind of duty.
    fn context(shut_down: bool) -> SigningContext {
        let config = Config::mainnet().with_fork_epoch(ForkName::Gloas, 0);
        SigningContext::new(config, Root::ZERO).with_slashed(SlashedValidators::new(shut_down))
    }

    fn settings() -> ProposerSettings {
        ProposerSettings::new(Bytes32::ZERO, Some(H160([0xab; 20])))
    }

    async fn refresh(
        node: &Arc<MockBeaconNode>,
        duties: &mut DutiesService<MockBeaconNode>,
        context: &SigningContext,
    ) -> crate::Result<Refreshed> {
        let keys = [pubkey(1), pubkey(2)];
        refresh_epoch(node, duties, &keys, 3, &settings(), context).await
    }

    /// Without the flag a slashed key does not stop the client: it is
    /// counted, gets none of its proposer, attester or aggregation duties, and
    /// is left out of builder registrations and fee recipient preparations,
    /// the epoch's and the per-slot re-send's. It keeps its sync committee
    /// and payload timeliness duties, which the chain still counts, and the
    /// other key keeps all of its own.
    #[tokio::test]
    async fn a_slashed_key_loses_its_proposals_attestations_and_sends_and_keeps_the_rest() {
        let node = Arc::new(node());
        let mut duties = DutiesService::new(node.clone(), Vec::new());
        let context = context(false);

        let Refreshed {
            registrable,
            resolved,
            ..
        } = refresh(&node, &mut duties, &context)
            .await
            .expect("a slashed key does not stop the client without the flag");

        // The count `ethlambda_validator_validators_slashed` is set to. The
        // gauge itself is one per process, which every refresh test running
        // in parallel writes.
        assert_eq!(context.slashed().count(), 1);
        assert!(context.slashed().contains(&pubkey(2)));

        let attesters = |slot, epoch| -> Vec<ValidatorIndex> {
            let held = duties.at_slot(slot, epoch);
            held.iter().map(|duty| duty.validator_index).collect()
        };
        assert_eq!(attesters(100, 3), [11]);
        assert_eq!(attesters(130, 4), [11]);
        assert_eq!(attesters(131, 4), Vec::<ValidatorIndex>::new());
        assert!(duties.all().iter().all(|duty| duty.validator_index == 11));
        assert_eq!(
            duties
                .proposer_at_slot(97, 3)
                .map(|duty| duty.validator_index),
            Some(11)
        );
        assert!(duties.proposer_at_slot(98, 3).is_none());
        let committee: Vec<ValidatorIndex> = duties
            .ptc_at_slot(99, 3)
            .iter()
            .map(|duty| duty.validator_index)
            .collect();
        assert_eq!(committee, [11, 22]);
        let sync: Vec<ValidatorIndex> = duties
            .sync_for_period(0)
            .iter()
            .map(|duty| duty.validator_index)
            .collect();
        assert_eq!(sync, [11, 22]);
        let subscribed: Vec<ValidatorIndex> = node
            .sync_subscriptions()
            .iter()
            .map(|subscription| subscription.validator_index)
            .collect();
        assert_eq!(subscribed, [11, 22]);

        assert_eq!(registrable, [pubkey(1)]);
        let prepared: Vec<ValidatorIndex> = node
            .preparations()
            .iter()
            .map(|preparation| preparation.validator_index)
            .collect();
        assert_eq!(prepared, [11], "the refresh's own send");
        let resent: Vec<ValidatorIndex> = preparations(&resolved, &settings())
            .iter()
            .map(|preparation| preparation.validator_index)
            .collect();
        assert_eq!(resent, [11], "and the per-slot re-send");
    }

    /// With the flag, the refresh that finds a slashed key stops the client
    /// before it fetches or sends anything else, with the error the binary
    /// exits with `EXIT_CODE` for. Not retryable, so the duty loop stops on it
    /// rather than trying again the next slot, and `run` returns it once the
    /// keymanager has finished.
    #[tokio::test]
    async fn with_the_flag_a_slashed_key_stops_the_client_before_anything_is_sent() {
        let node = Arc::new(node());
        let mut duties = DutiesService::new(node.clone(), Vec::new());

        let err = refresh(&node, &mut duties, &context(true))
            .await
            .expect_err("the flag stops the client");
        assert!(
            matches!(&err, Error::ValidatorSlashed { validators } if *validators == [22]),
            "got {err}"
        );
        assert!(!err.is_retryable());
        assert_eq!(node.duties_call_count(), 0);
        assert!(node.preparations().is_empty());

        let protection = slashing_protection::SlashingProtection::in_memory();
        let stopped =
            run_until_stopped(async { err }, &protection, CancellationToken::new(), None).await;
        assert!(
            matches!(stopped, Error::ValidatorSlashed { .. }),
            "got {stopped}"
        );
    }

    /// The flag alone stops nothing: a refresh with no slashed key goes on.
    #[tokio::test]
    async fn with_the_flag_and_no_slashed_key_the_refresh_goes_on() {
        let mut node = node();
        node.validators[1].slashed = false;
        node.validators[1].status = "active_ongoing".to_string();
        let node = Arc::new(node);
        let mut duties = DutiesService::new(node.clone(), Vec::new());

        refresh(&node, &mut duties, &context(true))
            .await
            .expect("nothing is slashed");
        assert_eq!(duties.at_slot(100, 3).len(), 2);
    }
}
