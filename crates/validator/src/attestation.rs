//! Producing and publishing this slot's attestations.

use std::sync::Arc;

use ethlambda_types::beacon::containers::shared::AttestationData;
use ethlambda_types::beacon::primitives::Slot;
use ethlambda_types::beacon::signing::compute_epoch_at_slot;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::attestation_guard::AttestationGuard;
use crate::beacon_node::dto::{
    AttestationDataOutDto, AttesterDutyDto, SingleAttestationDto, encode_hex, parse_pubkey,
};
use crate::beacon_node::{BeaconNodeApi, validate_attestation_data};
use crate::error::Result;
use crate::keys::ValidatorStore;
use crate::signing::SigningContext;

/// What one slot's attestation duty produced.
///
/// The data is carried out alongside the count because the aggregation duty
/// later in the same slot needs it, and needs *this* one: it identifies the
/// aggregate covering the votes these validators just cast. Re-fetching it
/// there would ask the beacon node again, and a head that moved in between
/// would give different data whose aggregate contains none of them. See
/// [`crate::aggregation`].
#[derive(Debug, Clone)]
pub struct Attested {
    /// How many attestations the beacon node accepted.
    pub published: usize,
    /// The data every attestation in this slot was signed over, or `None` when
    /// there was no duty to fetch it for.
    ///
    /// An `Option` rather than a zeroed default, because a caller handed a
    /// default would ask for the aggregate of an attestation nobody made. It is
    /// `Some` whenever the fetch succeeded, even if nothing was published:
    /// aggregation is a duty over the *whole committee's* votes, so it is still
    /// owed when this client's own signatures were refused.
    pub data: Option<AttestationData>,
}

pub struct AttestationService<B> {
    beacon_node: Arc<B>,
    context: Arc<SigningContext>,
    /// What this process has already signed, per validator.
    ///
    /// A `std::sync::Mutex` rather than a `tokio` one on purpose: the critical
    /// section is a hash lookup and an insert with no `.await` inside it, so an
    /// async mutex would buy nothing and cost a scheduling point. The guard is
    /// taken and dropped per validator inside the signing loop, which already
    /// holds the store's read lock, so it must not be the thing that blocks.
    ///
    /// Not slashing protection. See [`AttestationGuard`] for exactly what it
    /// does and does not cover.
    guard: std::sync::Mutex<AttestationGuard>,
}

impl<B: BeaconNodeApi> AttestationService<B> {
    pub fn new(beacon_node: Arc<B>, context: Arc<SigningContext>) -> Self {
        Self {
            beacon_node,
            context,
            guard: std::sync::Mutex::new(AttestationGuard::new()),
        }
    }

    /// Sign and publish every duty held for `slot`.
    ///
    /// One `attestation_data` fetch is shared by every validator attesting at
    /// this slot, and every signature goes out in one submission: the data does
    /// not depend on the validator, and the beacon node's pool endpoint takes a
    /// list.
    ///
    /// Returns how many attestations were published, and the data they were
    /// signed over, which this slot's aggregation duty needs.
    ///
    /// # Do not retry this call within a slot
    ///
    /// On a submission failure every signature in the batch has already been
    /// produced. Calling this again re-fetches the attestation data, and if the
    /// head moved in between it signs a *different* message for the same
    /// validator and slot. This client keeps no slashing-protection record, so
    /// nothing would catch that, and two distinct attestations for one slot from
    /// one validator is a slashable offence.
    ///
    /// A caller that wants to retry must resubmit the batch this call already
    /// built, not call this again. Today's duty loop does neither: it logs the
    /// failure and waits for the next slot, which is the safe default.
    ///
    /// The `Eth-Consensus-Version` header is derived here from the fetched
    /// attestation data's target epoch, rather than taken from the caller: a
    /// caller-supplied fork name could be stale across a fork boundary with
    /// nothing to catch it, whereas the target epoch is what the signing
    /// domain is already keyed on for this same message.
    pub async fn attest(
        &self,
        slot: Slot,
        duties: &[AttesterDutyDto],
        store: &RwLock<ValidatorStore>,
    ) -> Result<Attested> {
        if duties.is_empty() {
            return Ok(Attested {
                published: 0,
                data: None,
            });
        }

        // The fork of the slot, by this client's own schedule, tells the node
        // which form of the query to answer: from gloas the `committee_index`
        // is omitted and the answer's `index` is the payload signal. It is
        // signed as received, never reset to zero.
        let slot_fork = self
            .context
            .config
            .fork_at_epoch(compute_epoch_at_slot(slot));
        let data = self.beacon_node.attestation_data(slot, slot_fork).await?;

        // Checked again here, having already been checked by the
        // implementation this call went through (see the contract on
        // `BeaconNodeApi::attestation_data`). Not redundant: the trait is
        // public, so this is the last point at which a wrong answer from an
        // implementation that failed to honour its contract can be stopped
        // before it becomes a signature.
        //
        // This is *not* where failover happens, and an earlier comment here
        // wrongly said it was. `FallbackBeaconNode` wraps the call above, so by
        // the time this runs a node's answer has already been accepted and
        // returned; failing here loses the slot rather than trying the next
        // node. That is why the same check now lives in the implementation,
        // where an `Err` is something failover can act on.
        validate_attestation_data(slot, &data)?;

        // Consistent with the check just above: `data.target.epoch` is now
        // known to equal `expected_target_epoch`, so this is the fork this
        // attestation actually signs under.
        let fork_name = self
            .context
            .config
            .fork_at_epoch(data.target.epoch)
            .as_str();

        let data_dto = AttestationDataOutDto::from(&data);

        // The read guard is scoped to this block alone and must never be widened to cover an
        // await. `tokio::sync::RwLock` is write-preferring, so a keymanager
        // import or delete queuing for the write lock blocks every read behind
        // it; keeping this guard narrow bounds how long that wait can be. The
        // import holds its own write lock for the inserts alone, doing the slow
        // EIP-2335 derivation outside it (see `http_api::keystores::import`),
        // so this is the duty path keeping its half of the same bargain.
        let mut attestations = Vec::with_capacity(duties.len());
        {
            let _timing = crate::metrics::time_signing();
            let store = store.read().await;
            for duty in duties {
                let pubkey = match parse_pubkey(&duty.pubkey) {
                    Ok(pubkey) => pubkey,
                    Err(err) => {
                        error!(%slot, validator = duty.validator_index, %err, "Duty carried an unreadable pubkey");
                        continue;
                    }
                };

                // Refuse before signing, not after: a signature that exists is
                // a signature that can escape, whatever the code after it
                // intended. This closes the double-vote shapes reachable
                // within one run (a backward clock step, a schedule replaced
                // mid-epoch); it is not slashing protection and does not
                // pretend to be. See `AttestationGuard`.
                //
                // Held per validator, and dropped before the next iteration.
                // The lock is poisoned only by a panic while it is held, and
                // nothing inside can panic; `unwrap` on it would still be a
                // crash in the duty path, so a poisoned lock is treated as a
                // refusal for every remaining validator instead.
                match self.guard.lock() {
                    Ok(mut guard) => {
                        if let Err(refusal) = guard.check_and_record(&pubkey, &data) {
                            warn!(
                                %slot,
                                validator = duty.validator_index,
                                %refusal,
                                "Refusing to sign: this process already signed a conflicting \
                                 attestation for this validator"
                            );
                            crate::metrics::inc_attestations_refused();
                            continue;
                        }
                    }
                    Err(err) => {
                        error!(%slot, %err, "Attestation guard is poisoned; refusing to sign");
                        crate::metrics::inc_attestations_refused();
                        continue;
                    }
                }

                // One validator failing must not cost the others their attestation.
                let signature = match self.context.sign_attestation(&store, &pubkey, &data) {
                    Ok(signature) => signature,
                    Err(err) => {
                        error!(%slot, validator = duty.validator_index, %err, "Failed to sign attestation");
                        crate::metrics::inc_signing_failures();
                        continue;
                    }
                };

                attestations.push(SingleAttestationDto {
                    committee_index: duty.committee_index,
                    attester_index: duty.validator_index,
                    data: data_dto.clone(),
                    signature: encode_hex(&signature.0),
                });
            }
        }

        if attestations.is_empty() {
            return Ok(Attested {
                published: 0,
                data: Some(data),
            });
        }

        let submitted = attestations.len();
        let published = self
            .beacon_node
            .submit_attestations(&attestations, fork_name)
            .await?;
        if published < submitted {
            warn!(
                %slot,
                published,
                submitted,
                "Some attestations in this slot's batch were rejected by the beacon node"
            );
        }
        info!(%slot, count = published, "Published attestations");
        crate::metrics::inc_attestations_published(published as u64);
        Ok(Attested {
            published,
            data: Some(data),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Used by the tests only: the signing path itself no longer constructs an
    // error, since `validate_attestation_data` produces them now.
    use crate::beacon_node::mock::MockBeaconNode;
    use crate::error::Error;
    use ethlambda_types::beacon::config::Config;
    use ethlambda_types::beacon::containers::shared::{AttestationData, Checkpoint};
    use ethlambda_types::beacon::preset;
    use ethlambda_types::beacon::primitives::Root;

    fn secret() -> [u8; 32] {
        hex::decode("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            .expect("valid hex")
            .try_into()
            .expect("32 bytes")
    }

    /// A second, unrelated key.
    ///
    /// Tests that exercise two duties in one slot need two *validators*, not
    /// one key used twice. A pubkey resolves to exactly one validator index on
    /// chain, and `ValidatorStore` is keyed by pubkey so a duplicate collapses,
    /// so one key under two indices is a shape that cannot occur. It also now
    /// trips `AttestationGuard`, correctly: two duties for one validator in one
    /// epoch is the double-vote shape the guard exists to refuse.
    fn other_secret() -> [u8; 32] {
        let mut bytes = secret();
        // Perturb a low byte: still a valid scalar, comfortably below the
        // curve order, and a different key from `secret()`.
        bytes[31] ^= 0x01;
        bytes
    }

    fn context() -> Arc<SigningContext> {
        Arc::new(SigningContext {
            config: Config::mainnet(),
            genesis_validators_root: Root::ZERO,
        })
    }

    fn duty(
        pubkey: &str,
        validator_index: u64,
        slot: u64,
        committee_index: u64,
    ) -> AttesterDutyDto {
        AttesterDutyDto {
            pubkey: pubkey.to_string(),
            validator_index,
            committee_index,
            committee_length: 128,
            committees_at_slot: 64,
            validator_committee_index: 7,
            slot,
        }
    }

    #[tokio::test]
    async fn signs_and_submits_one_attestation_per_duty() {
        let mut store = ValidatorStore::new();
        let first = store.insert_secret("test", &secret()).expect("inserts");
        let second = store
            .insert_secret("test-2", &other_secret())
            .expect("inserts");

        let node = Arc::new(MockBeaconNode::new().with_attestation_data(96));
        let service = AttestationService::new(node.clone(), context());

        let duties = vec![
            duty(&encode_hex(&first.0), 1337, 96, 3),
            duty(&encode_hex(&second.0), 1338, 96, 3),
        ];
        let store = RwLock::new(store);
        let published = service.attest(96, &duties, &store).await.expect("attests");

        assert_eq!(published.published, 2);
        let submitted = node.submitted();
        assert_eq!(submitted.len(), 2);
        assert_eq!(submitted[0].attester_index, 1337);
        assert_eq!(submitted[1].attester_index, 1338);
        assert_eq!(submitted[0].committee_index, 3);
        assert_eq!(
            node.attestation_data_call_count(),
            1,
            "the data must be fetched once and shared"
        );
    }

    /// The guard engaging in the real signing path, not just in isolation.
    ///
    /// This is the backward-clock-step shape: the duty loop derives its slot
    /// from the wall clock, so an NTP correction can re-enter a slot already
    /// attested and call `attest` again for it. The first call must publish;
    /// the second must publish nothing and must not reach the beacon node with
    /// a second signature.
    #[tokio::test]
    async fn attesting_the_same_slot_twice_publishes_only_once() {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");

        let node = Arc::new(MockBeaconNode::new().with_attestation_data(96));
        let service = AttestationService::new(node.clone(), context());

        let duties = vec![duty(&encode_hex(&pubkey.0), 1337, 96, 3)];
        let store = RwLock::new(store);

        let first = service.attest(96, &duties, &store).await.expect("attests");
        let second = service
            .attest(96, &duties, &store)
            .await
            .expect("the second call is not an error, it simply signs nothing");

        assert_eq!(first.published, 1);
        assert_eq!(second.published, 0, "the second attempt must be refused");
        assert_eq!(
            node.submitted().len(),
            1,
            "only one signature may ever reach the beacon node"
        );
    }

    /// The mid-epoch schedule replacement shape: the same validator moved to a
    /// different slot within one epoch. Both slots are in epoch 3, so the
    /// second is a double vote even though the slot differs.
    #[tokio::test]
    async fn attesting_a_second_slot_in_one_epoch_is_refused() {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        let pubkey_hex = encode_hex(&pubkey.0);

        // 96 and 101 are both in epoch 3 (96 / 32 == 101 / 32 == 3).
        let node = Arc::new(MockBeaconNode::new().with_attestation_data(96));
        let service = AttestationService::new(node.clone(), context());
        let store = RwLock::new(store);

        let first = service
            .attest(96, &[duty(&pubkey_hex, 1337, 96, 3)], &store)
            .await
            .expect("attests");
        assert_eq!(first.published, 1);

        let node_again = Arc::new(MockBeaconNode::new().with_attestation_data(101));
        // Same service, so the same guard; a new mock only because the mock
        // pins one slot's data at a time.
        let service = AttestationService {
            beacon_node: node_again.clone(),
            context: context(),
            guard: service.guard,
        };
        let second = service
            .attest(101, &[duty(&pubkey_hex, 1337, 101, 3)], &store)
            .await
            .expect("not an error, simply signs nothing");

        assert_eq!(
            second.published, 0,
            "a second slot in one target epoch must be refused"
        );
        assert!(node_again.submitted().is_empty());
    }

    /// Distinct from the test above: both duties there share one committee
    /// index, so it cannot tell "each duty's own committee index is
    /// forwarded" apart from "the shared attestation data leaked its index
    /// into every output". Here the two duties disagree, which only the
    /// former explains.
    #[tokio::test]
    async fn each_duty_keeps_its_own_committee_index() {
        let mut store = ValidatorStore::new();
        let first = store.insert_secret("test", &secret()).expect("inserts");
        let second = store
            .insert_secret("test-2", &other_secret())
            .expect("inserts");

        let node = Arc::new(MockBeaconNode::new().with_attestation_data(96));
        let service = AttestationService::new(node.clone(), context());

        let duties = vec![
            duty(&encode_hex(&first.0), 1337, 96, 3),
            duty(&encode_hex(&second.0), 1338, 96, 5),
        ];
        let store = RwLock::new(store);
        let published = service.attest(96, &duties, &store).await.expect("attests");

        assert_eq!(published.published, 2);
        let submitted = node.submitted();
        assert_eq!(submitted[0].committee_index, 3);
        assert_eq!(submitted[1].committee_index, 5);
        assert_eq!(
            node.attestation_data_call_count(),
            1,
            "the data must still be fetched once and shared"
        );
    }

    #[tokio::test]
    async fn a_validator_without_a_key_does_not_block_the_others() {
        let mut store = ValidatorStore::new();
        let known = store.insert_secret("test", &secret()).expect("inserts");

        let node = Arc::new(MockBeaconNode::new().with_attestation_data(96));
        let service = AttestationService::new(node.clone(), context());

        let duties = vec![
            duty(&encode_hex(&[0x99; 48]), 1, 96, 3),
            duty(&encode_hex(&known.0), 1337, 96, 3),
        ];
        let store = RwLock::new(store);
        let published = service.attest(96, &duties, &store).await.expect("attests");

        assert_eq!(published.published, 1);
        assert_eq!(node.submitted()[0].attester_index, 1337);
    }

    #[tokio::test]
    async fn nothing_is_submitted_when_every_validator_failed_to_sign() {
        // Distinct from `no_duties_means_no_request_at_all`: that test hits
        // the early `duties.is_empty()` guard before any fetch happens. This
        // one has duties, so the fetch does happen, and exercises the guard
        // after the signing loop, where the loop produced nothing to send.
        let store = RwLock::new(ValidatorStore::new());
        let node = Arc::new(MockBeaconNode::new().with_attestation_data(96));
        let service = AttestationService::new(node.clone(), context());

        let duties = vec![
            duty(&encode_hex(&[0x99; 48]), 1, 96, 3),
            duty(&encode_hex(&[0x88; 48]), 2, 96, 3),
        ];
        let published = service.attest(96, &duties, &store).await.expect("attests");

        assert_eq!(published.published, 0);
        assert!(node.submitted().is_empty());
        assert_eq!(
            node.attestation_data_call_count(),
            1,
            "the fetch still happens; only the submission is skipped"
        );
    }

    /// The aggregation duty later in the slot asks for the aggregate covering
    /// exactly this data, so it has to come back from here rather than be
    /// re-fetched: a head that moved in between would give different data
    /// whose aggregate contains none of these votes.
    #[tokio::test]
    async fn the_attested_data_is_handed_back_for_aggregation() {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        let store = RwLock::new(store);
        let node = Arc::new(MockBeaconNode::new().with_attestation_data(96));
        let service = AttestationService::new(node, context());

        let attested = service
            .attest(96, &[duty(&encode_hex(&pubkey.0), 1337, 96, 3)], &store)
            .await
            .expect("attests");

        let data = attested.data.expect("the fetched data must come back");
        assert_eq!(data.slot, 96);
        assert_eq!(data.target.epoch, 3);
    }

    /// With no duty there is nothing to fetch, so there is no data either.
    /// A zeroed default here would have the aggregation duty ask for the
    /// aggregate of an attestation nobody made.
    #[tokio::test]
    async fn no_duties_means_no_data_to_aggregate_against() {
        let service = AttestationService::new(Arc::new(MockBeaconNode::new()), context());
        let attested = service
            .attest(96, &[], &RwLock::new(ValidatorStore::new()))
            .await
            .expect("no-op");
        assert!(attested.data.is_none());
    }

    #[tokio::test]
    async fn no_duties_means_no_request_at_all() {
        let node = Arc::new(MockBeaconNode::new());
        let service = AttestationService::new(node.clone(), context());
        let published = service
            .attest(96, &[], &RwLock::new(ValidatorStore::new()))
            .await
            .expect("no-op");
        assert_eq!(published.published, 0);
        assert_eq!(node.attestation_data_call_count(), 0);
    }

    #[tokio::test]
    async fn a_failing_attestation_data_fetch_is_reported() {
        let node = Arc::new(MockBeaconNode::new());
        let service = AttestationService::new(node, context());
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        let store = RwLock::new(store);
        let err = service
            .attest(96, &[duty(&encode_hex(&pubkey.0), 1, 96, 0)], &store)
            .await
            .expect_err("must fail");
        assert!(err.to_string().contains("no attestation data"), "got {err}");
    }

    /// The regression test for the missing check this finding is about: a
    /// beacon node primed for slot 96 answers a request for slot 97 with
    /// that stale data, `data.slot` (96) disagreeing with the requested slot
    /// (97). Before the fix in `attest`, nothing compared the two and the
    /// mismatched data was signed and submitted anyway.
    #[tokio::test]
    async fn attestation_data_for_the_wrong_slot_is_rejected() {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        let store = RwLock::new(store);
        let pubkey_hex = encode_hex(&pubkey.0);

        let node = Arc::new(MockBeaconNode::new().with_attestation_data(96));
        let service = AttestationService::new(node.clone(), context());

        let duties = vec![duty(&pubkey_hex, 1337, 97, 3)];
        let err = service
            .attest(97, &duties, &store)
            .await
            .expect_err("must reject data answering for a different slot");

        assert!(matches!(err, Error::InconsistentResponse(_)), "got {err:?}");
        assert!(
            node.submitted().is_empty(),
            "a mismatched response must never be signed or submitted"
        );
    }

    /// Distinct from the slot check above: here the slot the node answers
    /// with matches what was asked for, but the target checkpoint's epoch
    /// does not correspond to that slot. Since the signing domain is chosen
    /// from `data.target.epoch`, this is an independent way a broken node
    /// could get a signature out of this client that it should not.
    #[tokio::test]
    async fn attestation_data_with_a_target_epoch_inconsistent_with_its_slot_is_rejected() {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        let store = RwLock::new(store);
        let pubkey_hex = encode_hex(&pubkey.0);

        let mut node = MockBeaconNode::new();
        node.attestation_data = Some(AttestationData {
            slot: 96,
            index: 0,
            beacon_block_root: Root::ZERO,
            source: Checkpoint {
                epoch: 0,
                root: Root::ZERO,
            },
            // Slot 96 belongs to epoch 3 (96 / 32); 999 is deliberately wrong.
            target: Checkpoint {
                epoch: 999,
                root: Root::ZERO,
            },
        });
        let node = Arc::new(node);
        let service = AttestationService::new(node.clone(), context());

        let duties = vec![duty(&pubkey_hex, 1337, 96, 3)];
        let err = service
            .attest(96, &duties, &store)
            .await
            .expect_err("must reject an internally inconsistent target epoch");

        assert!(matches!(err, Error::InconsistentResponse(_)), "got {err:?}");
        assert!(node.submitted().is_empty());
    }

    /// The regression test for why `attest` derives the `Eth-Consensus-Version`
    /// header from `data.target.epoch` rather than accepting it from the
    /// caller: the two slots below are one epoch apart and straddle mainnet's
    /// altair boundary, so if the header were derived from anything else (a
    /// cached value, the wrong epoch, an off-by-one), at least one assertion
    /// here would fail. A case where the two epochs' forks agree would not
    /// tell them apart.
    #[tokio::test]
    async fn the_consensus_version_header_tracks_the_target_epochs_fork() {
        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        let pubkey_hex = encode_hex(&pubkey.0);
        let store = RwLock::new(store);

        let altair_fork_epoch = Config::mainnet().altair_fork_epoch;
        let last_phase0_slot = altair_fork_epoch * preset::SLOTS_PER_EPOCH - 1;
        let first_altair_slot = altair_fork_epoch * preset::SLOTS_PER_EPOCH;

        let phase0_node = Arc::new(MockBeaconNode::new().with_attestation_data(last_phase0_slot));
        AttestationService::new(phase0_node.clone(), context())
            .attest(
                last_phase0_slot,
                &[duty(&pubkey_hex, 1337, last_phase0_slot, 3)],
                &store,
            )
            .await
            .expect("attests");

        let altair_node = Arc::new(MockBeaconNode::new().with_attestation_data(first_altair_slot));
        AttestationService::new(altair_node.clone(), context())
            .attest(
                first_altair_slot,
                &[duty(&pubkey_hex, 1337, first_altair_slot, 3)],
                &store,
            )
            .await
            .expect("attests");

        assert_eq!(
            phase0_node.last_submitted_fork_name().as_deref(),
            Some("phase0")
        );
        assert_eq!(
            altair_node.last_submitted_fork_name().as_deref(),
            Some("altair")
        );
    }

    fn gloas_context() -> Arc<SigningContext> {
        Arc::new(SigningContext {
            config: Config::mainnet()
                .with_fork_epoch(ethlambda_types::beacon::fork::ForkName::Gloas, 10),
            genesis_validators_root: Root::ZERO,
        })
    }

    /// From gloas `data.index` is the payload signal, so a node answering 1
    /// must see it submitted as 1 and signed as 1: resetting it to zero, as
    /// the electra rule would suggest, signs a vote the node never made.
    #[tokio::test]
    async fn a_gloas_index_of_one_is_submitted_and_signed_unchanged() {
        use blst::min_pk::{PublicKey, Signature};
        use ethlambda_types::beacon::fork::ForkName;

        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        let pubkey_hex = encode_hex(&pubkey.0);
        let store = RwLock::new(store);

        let slot = 10 * preset::SLOTS_PER_EPOCH + 3;
        let node = Arc::new(
            MockBeaconNode::new()
                .with_attestation_data(slot)
                .with_attestation_index(1),
        );
        let attested = AttestationService::new(node.clone(), gloas_context())
            .attest(slot, &[duty(&pubkey_hex, 1337, slot, 3)], &store)
            .await
            .expect("attests");

        assert_eq!(attested.data.expect("data").index, 1);
        let submitted = node.submitted();
        assert_eq!(submitted.len(), 1);
        assert_eq!(submitted[0].data.index, 1, "the index must pass through");
        assert_eq!(node.last_submitted_fork_name().as_deref(), Some("gloas"));
        assert_eq!(node.attestation_data_forks(), vec![ForkName::Gloas]);

        // The signature is over the data with index 1, not over a zeroed copy.
        let mut signed_over = node.attestation_data.expect("set");
        assert_eq!(signed_over.index, 1);
        let root = gloas_context().attestation_signing_root(&signed_over);
        let signature_bytes: [u8; 96] =
            hex::decode(submitted[0].signature.trim_start_matches("0x"))
                .expect("hex")
                .try_into()
                .expect("96 bytes");
        let pk = PublicKey::from_bytes(&pubkey.0).expect("valid pubkey");
        let sig = Signature::from_bytes(&signature_bytes).expect("valid signature");
        let verify = |root: Root| {
            sig.verify(
                true,
                root.as_slice(),
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
                &[],
                &pk,
                true,
            )
        };
        assert_eq!(verify(root), blst::BLST_ERROR::BLST_SUCCESS);

        signed_over.index = 0;
        assert_ne!(
            verify(gloas_context().attestation_signing_root(&signed_over)),
            blst::BLST_ERROR::BLST_SUCCESS,
            "a vote for index 0 is a different message"
        );
    }

    /// Slots before gloas are asked about under their own fork, so the HTTP
    /// client keeps sending `committee_index=0` there.
    #[tokio::test]
    async fn a_pre_gloas_slot_is_asked_about_under_its_own_fork() {
        use ethlambda_types::beacon::fork::ForkName;

        let mut store = ValidatorStore::new();
        let pubkey = store.insert_secret("test", &secret()).expect("inserts");
        let pubkey_hex = encode_hex(&pubkey.0);
        let store = RwLock::new(store);

        let slot = 9 * preset::SLOTS_PER_EPOCH + 3;
        let node = Arc::new(MockBeaconNode::new().with_attestation_data(slot));
        AttestationService::new(node.clone(), gloas_context())
            .attest(slot, &[duty(&pubkey_hex, 1337, slot, 3)], &store)
            .await
            .expect("attests");
        assert_eq!(node.attestation_data_forks(), vec![ForkName::Phase0]);
    }
}
